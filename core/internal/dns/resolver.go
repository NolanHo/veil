package dns

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"veil/internal/config"
	"veil/internal/transport"
)

const (
	// maxCacheEntries bounds the resolve cache; oldest entries are evicted.
	maxCacheEntries = 4096
	// negativeTTL is how long a failed lookup is remembered.
	negativeTTL = 5 * time.Second
	// queryTimeout bounds a single upstream attempt.
	queryTimeout = 5 * time.Second
	// defaultTTL is used when an upstream answer carries no usable TTL and is
	// also the TTL stamped on synthesized answers in Exchange.
	defaultTTL = 60
	// maxTTL caps how long we trust an upstream record.
	maxTTL = 3600
)

// state holds everything the resolver needs besides cfg/log/dial. It lives
// here (rather than in dns.go) so the public API file stays untouched.
type state struct {
	mu     sync.Mutex
	order  *list.List               // front = most recently used
	items  map[string]*list.Element // key -> element holding *cacheEntry
	flight map[string]*flight

	udpWarn sync.Once
}

func newState() *state {
	return &state{
		order:  list.New(),
		items:  make(map[string]*list.Element),
		flight: make(map[string]*flight),
	}
}

// cacheEntry is either a positive (addrs) or negative (err) result.
type cacheEntry struct {
	key     string
	addrs   []netip.Addr
	err     error
	expires time.Time
}

// flight is an in-progress lookup that concurrent callers wait on.
type flight struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// states maps *Resolver to its mutable state, so dns.go's public struct stays
// untouched.
var states sync.Map // *Resolver -> *state

func (r *Resolver) state() *state {
	if v, ok := states.Load(r); ok {
		return v.(*state)
	}
	v, _ := states.LoadOrStore(r, newState())
	return v.(*state)
}

func (r *Resolver) warnf(format string, args ...any) {
	if r.log != nil {
		r.log.Warnf(format, args...)
	}
}

func (r *Resolver) debugf(format string, args ...any) {
	if r.log != nil {
		r.log.Debugf(format, args...)
	}
}

// lookupDecision is beginLookup's answer: either a cached result, an in-flight
// lookup to wait on, or (leader) a flight the caller has to perform itself.
type lookupDecision struct {
	cached bool
	addrs  []netip.Addr
	err    error
	flight *flight
	leader bool
}

// beginLookup decides, under one lock, whether this caller is answered from the
// cache, joins a flight, or starts one. Cache check and flight registration have
// to be the same decision: taken separately, a caller that had already missed
// the cache could register a second flight after another caller's flight had
// finished and gone, sending the same name upstream twice.
func (st *state) beginLookup(key string, useCache bool, now time.Time) lookupDecision {
	st.mu.Lock()
	defer st.mu.Unlock()
	if useCache {
		if el, found := st.items[key]; found {
			ent := el.Value.(*cacheEntry)
			if now.After(ent.expires) {
				st.order.Remove(el)
				delete(st.items, key)
			} else {
				st.order.MoveToFront(el)
				return lookupDecision{cached: true, addrs: ent.addrs, err: ent.err}
			}
		}
	}
	if f, ok := st.flight[key]; ok {
		return lookupDecision{flight: f}
	}
	f := &flight{done: make(chan struct{})}
	st.flight[key] = f
	return lookupDecision{flight: f, leader: true}
}

func (st *state) cachePut(ent *cacheEntry) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if el, ok := st.items[ent.key]; ok {
		el.Value = ent
		st.order.MoveToFront(el)
		return
	}
	st.items[ent.key] = st.order.PushFront(ent)
	for st.order.Len() > maxCacheEntries {
		back := st.order.Back()
		if back == nil {
			break
		}
		st.order.Remove(back)
		delete(st.items, back.Value.(*cacheEntry).key)
	}
}

func (st *state) cacheLen() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.order.Len()
}

// lookup resolves host, serving from cache and collapsing concurrent identical
// queries into one upstream round trip.
func (r *Resolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := normalizeHost(host)
	if name == "" {
		return nil, errors.New("dns: empty host name")
	}
	if ip, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	st := r.state()
	useCache := r.cfg.Cache
	d := st.beginLookup(name, useCache, time.Now())
	if d.cached {
		return d.addrs, d.err
	}
	if !d.leader {
		select {
		case <-d.flight.done:
			return d.flight.addrs, d.flight.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	addrs, ttl, err := r.resolve(ctx, name)
	if err == nil && len(addrs) == 0 {
		err = fmt.Errorf("dns: no addresses for %s", name)
	}
	store := useCache && ctx.Err() == nil
	if store {
		ent := &cacheEntry{key: name, addrs: addrs, expires: time.Now().Add(ttl)}
		if err != nil {
			ent.addrs = nil
			ent.err = err
			ent.expires = time.Now().Add(negativeTTL)
		}
		st.cachePut(ent)
	}

	st.mu.Lock()
	if st.flight[name] == d.flight {
		delete(st.flight, name)
	}
	st.mu.Unlock()
	d.flight.addrs, d.flight.err = addrs, err
	close(d.flight.done)
	if r.log != nil {
		if err != nil {
			r.log.Debugf("dns %s -> error: %v", name, err)
		} else {
			r.log.Debugf("dns %s -> %v", name, addrs)
		}
	}
	return addrs, err
}

// resolve walks the configured upstreams in priority order.
func (r *Resolver) resolve(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	ups := r.upstreamsFor(host)
	if len(ups) == 0 {
		return nil, 0, errors.New("dns: no upstream servers configured")
	}
	var lastErr error
	for _, u := range ups {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		addrs, ttl, err := r.queryServer(ctx, u, host)
		if err != nil {
			lastErr = err
			continue
		}
		return addrs, ttl, nil
	}
	return nil, 0, lastErr
}

// queryServer asks one upstream for A and AAAA records.
func (r *Resolver) queryServer(ctx context.Context, u upstream, host string) ([]netip.Addr, time.Duration, error) {
	var (
		addrs    []netip.Addr
		ttl      = time.Duration(defaultTTL) * time.Second
		firstErr error
	)
	for _, qt := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		msg, err := r.queryType(ctx, u, host, qt)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("dns: %s: query %s: %w", u.display, mdns.TypeToString[qt], err)
			}
			continue
		}
		switch msg.Rcode {
		case mdns.RcodeSuccess:
			got := collectAddrs(msg, qt)
			if len(got) == 0 {
				continue
			}
			addrs = appendUnique(addrs, got...)
			if t := minTTL(msg); t > 0 && t < ttl {
				ttl = t
			}
		case mdns.RcodeNameError:
			if firstErr == nil {
				firstErr = fmt.Errorf("dns: %s: NXDOMAIN for %s", u.display, host)
			}
		default:
			if firstErr == nil {
				firstErr = fmt.Errorf("dns: %s: rcode %s for %s", u.display, mdns.RcodeToString[msg.Rcode], host)
			}
		}
	}
	if len(addrs) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("dns: %s: no address records for %s", u.display, host)
		}
		return nil, 0, firstErr
	}
	return addrs, ttl, nil
}

func (r *Resolver) queryType(ctx context.Context, u upstream, host string, qtype uint16) (*mdns.Msg, error) {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(host), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)

	switch u.scheme {
	case "udp":
		return r.queryUDP(ctx, u, m)
	case "tcp":
		return r.queryTCP(ctx, u, m)
	case "tls":
		return r.queryTLS(ctx, u, m)
	case "https":
		return r.queryDOH(ctx, u, m)
	default:
		return nil, fmt.Errorf("dns: unsupported scheme %q", u.scheme)
	}
}

// queryUDP sends a plain UDP query. When a detour dialer is installed a stream
// connection cannot carry UDP, so we try DNS-over-TCP through the detour first
// and fall back to a direct UDP socket (warning once).
func (r *Resolver) queryUDP(ctx context.Context, u upstream, m *mdns.Msg) (*mdns.Msg, error) {
	if r.dial != nil {
		if msg, err := r.queryTCP(ctx, u, m); err == nil {
			return msg, nil
		} else {
			r.state().udpWarn.Do(func() {
				r.warnf("dns: udp upstream %s unavailable via detour (%v); using direct UDP", u.display, err)
			})
		}
	}
	deadline := attemptDeadline(ctx)
	d := transport.NewDialer()
	conn, err := d.DialContext(ctx, "udp", u.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	out, err := m.Pack()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, fmt.Errorf("dns: malformed UDP response: %w", err)
	}
	if resp.Truncated {
		// Retry over TCP to get the full answer.
		return r.queryTCP(ctx, u, m)
	}
	return resp, nil
}

func (r *Resolver) queryTCP(ctx context.Context, u upstream, m *mdns.Msg) (*mdns.Msg, error) {
	conn, err := r.streamConn(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return exchangeStream(conn, m, attemptDeadline(ctx))
}

func (r *Resolver) queryTLS(ctx context.Context, u upstream, m *mdns.Msg) (*mdns.Msg, error) {
	tlsCfg := &tls.Config{ServerName: u.serverName(), MinVersion: tls.VersionTLS12}
	var conn net.Conn
	if r.dial != nil {
		raw, err := r.dial(ctx, "tcp", u.addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		conn = tc
	} else {
		td := &tls.Dialer{NetDialer: transport.NewDialer(), Config: tlsCfg}
		c, err := td.DialContext(ctx, "tcp", u.addr)
		if err != nil {
			return nil, err
		}
		conn = c
	}
	defer conn.Close()
	return exchangeStream(conn, m, attemptDeadline(ctx))
}

func (r *Resolver) queryDOH(ctx context.Context, u upstream, m *mdns.Msg) (*mdns.Msg, error) {
	out, err := m.Pack()
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, u.url, bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := r.httpClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("dns: %s: http status %d", u.display, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	msg := new(mdns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("dns: malformed DoH response: %w", err)
	}
	return msg, nil
}

// httpClient builds a DoH client that routes through the injected dialer.
func (r *Resolver) httpClient() *http.Client {
	dial := r.dial
	tr := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dial != nil {
				return dial(ctx, network, addr)
			}
			d := transport.NewDialer()
			return d.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: tr}
}

func (r *Resolver) streamConn(ctx context.Context, network, addr string) (net.Conn, error) {
	if r.dial != nil {
		return r.dial(ctx, network, addr)
	}
	d := transport.NewDialer()
	return d.DialContext(ctx, network, addr)
}

// exchangeStream writes a length-prefixed query and reads the reply.
func exchangeStream(conn net.Conn, m *mdns.Msg, deadline time.Time) (*mdns.Msg, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	out, err := m.Pack()
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(frame, uint16(len(out)))
	copy(frame[2:], out)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("dns: malformed response: %w", err)
	}
	return resp, nil
}

func attemptDeadline(ctx context.Context) time.Time {
	d := time.Now().Add(queryTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(d) {
		return dl
	}
	return d
}

// upstream is a parsed config.DNSServer.
type upstream struct {
	scheme  string // udp | tcp | tls | https
	addr    string // host:port for udp/tcp/tls
	url     string // full URL for https
	host    string // host part (used for SNI)
	server  string // TLS server name override, if any
	display string
	tag     string
}

func (u upstream) serverName() string {
	if u.server != "" {
		return u.server
	}
	h := u.host
	if h == "" {
		return ""
	}
	return h
}

// parseUpstream understands "1.1.1.1:53", "udp://", "tcp://", "tls://" and
// "https://" forms.
func parseUpstream(addr string) (upstream, error) {
	raw := strings.TrimSpace(addr)
	if raw == "" {
		return upstream{}, errors.New("dns: empty server address")
	}
	u := upstream{display: raw}
	scheme := "udp"
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme = strings.ToLower(raw[:i])
		rest = raw[i+3:]
	}
	switch scheme {
	case "udp", "tcp":
		u.scheme = scheme
		host, port, err := splitHostPort(rest, "53")
		if err != nil {
			return upstream{}, err
		}
		u.host, u.addr = host, net.JoinHostPort(host, port)
	case "tls", "dot":
		u.scheme = "tls"
		host, port, err := splitHostPort(rest, "853")
		if err != nil {
			return upstream{}, err
		}
		u.host, u.addr = host, net.JoinHostPort(host, port)
	case "https", "doh", "http":
		// DoH uses wire-format POST. Plain "http://" is tolerated so local and
		// test resolvers work; production configs should use https://.
		u.scheme = "https"
		full := raw
		if !strings.HasPrefix(full, "http://") && !strings.HasPrefix(full, "https://") {
			full = "https://" + rest
		}
		pu, err := url.Parse(full)
		if err != nil {
			return upstream{}, fmt.Errorf("dns: bad DoH url %q: %w", addr, err)
		}
		if pu.Path == "" || pu.Path == "/" {
			pu.Path = "/dns-query"
		}
		u.url = pu.String()
		u.host = pu.Hostname()
	default:
		return upstream{}, fmt.Errorf("dns: unsupported scheme %q", scheme)
	}
	return u, nil
}

func splitHostPort(hostport, defPort string) (string, string, error) {
	hostport = strings.TrimSuffix(hostport, "/")
	if hostport == "" {
		return "", "", errors.New("dns: empty server host")
	}
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if h == "" || p == "" {
			return "", "", fmt.Errorf("dns: bad server address %q", hostport)
		}
		return h, p, nil
	}
	// No port: add the protocol default. Wrap IPv6 literals in brackets.
	h := strings.Trim(hostport, "[]")
	return h, defPort, nil
}

// upstreamsFor orders servers: best domain suffix match first, then cfg.Final,
// then the rest.
func (r *Resolver) upstreamsFor(host string) []upstream {
	var (
		matched []upstream
		rest    []upstream
		final   *upstream
	)
	for _, s := range r.cfg.Servers {
		u, err := parseUpstream(s.Addr)
		if err != nil {
			r.warnf("dns: skipping server %q: %v", s.Addr, err)
			continue
		}
		u.tag = s.Tag
		if r.cfg.Final != "" && (strings.EqualFold(s.Tag, r.cfg.Final) || s.Addr == r.cfg.Final) {
			c := u
			final = &c
		}
		if domainMatch(host, s.Domains) {
			matched = append(matched, u)
		} else {
			rest = append(rest, u)
		}
	}

	out := make([]upstream, 0, len(r.cfg.Servers)+1)
	seen := make(map[string]bool)
	push := func(u upstream) {
		key := u.scheme + "|" + u.addr + u.url
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, u)
	}
	for _, u := range matched {
		push(u)
	}
	if final != nil {
		push(*final)
	}
	for _, u := range rest {
		push(u)
	}
	return out
}

// domainMatch reports whether host falls under any of the suffix patterns.
func domainMatch(host string, patterns []string) bool {
	host = normalizeHost(host)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		p = strings.TrimPrefix(p, "*")
		p = strings.TrimPrefix(p, ".")
		p = strings.TrimSuffix(p, ".")
		if p == "" {
			continue
		}
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	return h
}

func collectAddrs(msg *mdns.Msg, qtype uint16) []netip.Addr {
	var out []netip.Addr
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *mdns.A:
			if qtype != mdns.TypeA {
				continue
			}
			if addr, ok := netip.AddrFromSlice(v.A); ok {
				out = append(out, addr.Unmap())
			}
		case *mdns.AAAA:
			if qtype != mdns.TypeAAAA {
				continue
			}
			if addr, ok := netip.AddrFromSlice(v.AAAA); ok {
				out = append(out, addr)
			}
		}
	}
	return out
}

// minTTL returns the smallest answer TTL as a duration, clamped to [1s, maxTTL].
func minTTL(msg *mdns.Msg) time.Duration {
	best := uint32(0)
	for _, rr := range msg.Answer {
		t := rr.Header().Ttl
		if best == 0 || t < best {
			best = t
		}
	}
	if best == 0 {
		return time.Duration(defaultTTL) * time.Second
	}
	if best < 1 {
		best = 1
	}
	if best > maxTTL {
		best = maxTTL
	}
	return time.Duration(best) * time.Second
}

func appendUnique(dst []netip.Addr, addrs ...netip.Addr) []netip.Addr {
	for _, a := range addrs {
		dup := false
		for _, e := range dst {
			if e == a {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, a)
		}
	}
	return dst
}

// Exchange answers a raw DNS query. It never panics: malformed input yields a
// FORMERR reply. A/AAAA queries are answered from lookup; anything else is
// answered NXDOMAIN.
const fakeIPTTL = 60

func (r *Resolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	var req mdns.Msg
	if err := req.Unpack(query); err != nil || len(req.Question) != 1 {
		return errorReply(query, mdns.RcodeFormatError), nil
	}
	q := req.Question[0]

	switch q.Qtype {
	case mdns.TypeA, mdns.TypeAAAA:
	default:
		return replyFor(&req, mdns.RcodeNameError, nil), nil
	}

	// Fake-IP: answer locally with a synthetic address and let the proxy
	// resolve the real name. No upstream query ever leaves the device, so
	// domestic resolvers can neither poison the answer nor see the hostname.
	//
	// Names the local network owns are excluded (see bypassFakeIP): a NAS or a
	// printer does not exist at the exit node, so it takes the upstream path and
	// gets the real answer, or a real NXDOMAIN.
	if r.fakeOn && !bypassFakeIP(q.Name) {
		if q.Qtype == mdns.TypeAAAA {
			// No AAAA: force clients onto IPv4 so every flow carries the
			// domain back to us.
			return replyFor(&req, mdns.RcodeSuccess, nil), nil
		}
		if ip := r.fake.ipFor(strings.TrimSuffix(q.Name, ".")); ip.IsValid() {
			return replyFor(&req, mdns.RcodeSuccess, []mdns.RR{&mdns.A{
				Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: fakeIPTTL},
				A:   net.IP(ip.AsSlice()),
			}}), nil
		}
		return replyFor(&req, mdns.RcodeNameError, nil), nil
	}

	addrs, err := r.lookup(ctx, q.Name)
	if err != nil {
		if ctx.Err() != nil {
			return replyFor(&req, mdns.RcodeServerFailure, nil), nil
		}
		return replyFor(&req, mdns.RcodeNameError, nil), nil
	}

	var rrs []mdns.RR
	for _, a := range addrs {
		switch {
		case q.Qtype == mdns.TypeA && a.Is4():
			rrs = append(rrs, &mdns.A{
				Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: defaultTTL},
				A:   net.IP(a.AsSlice()),
			})
		case q.Qtype == mdns.TypeAAAA && a.Is6():
			rrs = append(rrs, &mdns.AAAA{
				Hdr:  mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: defaultTTL},
				AAAA: net.IP(a.AsSlice()),
			})
		}
	}
	rcode := mdns.RcodeSuccess
	if len(rrs) == 0 {
		rcode = mdns.RcodeNameError
	}
	return replyFor(&req, rcode, rrs), nil
}

// replyFor builds a response preserving the query's ID, question and flags.
func replyFor(req *mdns.Msg, rcode int, answers []mdns.RR) []byte {
	resp := new(mdns.Msg)
	resp.MsgHdr = mdns.MsgHdr{
		Id:                 req.Id,
		Response:           true,
		Opcode:             req.Opcode,
		RecursionDesired:   req.RecursionDesired,
		RecursionAvailable: true,
		AuthenticatedData:  req.AuthenticatedData,
		CheckingDisabled:   req.CheckingDisabled,
		Rcode:              rcode,
	}
	if len(req.Question) > 0 {
		resp.Question = append(resp.Question, req.Question...)
	}
	resp.Answer = answers
	if len(answers) > 0 && req.IsEdns0() != nil {
		resp.SetEdns0(1232, false)
	}
	out, err := resp.Pack()
	if err != nil {
		// Last resort: a bare header-only SERVFAIL with the original ID.
		fallback := new(mdns.Msg)
		fallback.Id = req.Id
		fallback.Response = true
		fallback.Rcode = mdns.RcodeServerFailure
		if b, e := fallback.Pack(); e == nil {
			return b
		}
		return nil
	}
	return out
}

// errorReply synthesizes a header-only error response for unparsable input.
func errorReply(query []byte, rcode int) []byte {
	m := new(mdns.Msg)
	if len(query) >= 2 {
		m.Id = binary.BigEndian.Uint16(query[:2])
	}
	m.Response = true
	m.RecursionAvailable = true
	m.Rcode = rcode
	out, err := m.Pack()
	if err != nil {
		return nil
	}
	return out
}

// ensure config stays referenced if unused in future refactors
var _ = config.DNSServer{}
