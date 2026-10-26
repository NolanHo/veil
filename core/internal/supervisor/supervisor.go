// Package supervisor owns the process lifecycle around the engine.
//
// The contract with the UI is simple and honest: every state has a reason, the
// watchdog measures liveness instead of assuming it, and a failed subsystem is
// reported as degraded rather than hidden behind a green switch.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"veil/internal/config"
	"veil/internal/engine"
	"veil/internal/logx"
	"veil/internal/rpc"
	"veil/internal/state"
	"veil/internal/version"
)

// Host is the platform side of the tunnel: the HarmonyOS VPN extension that
// creates the tun device and protects the engine's own sockets.
type Host interface {
	Request(ctx context.Context, method string, params map[string]any) (map[string]any, error)
}

// Supervisor is the single owner of the engine.
type Supervisor struct {
	cfgPath string
	log     *logx.Logger

	opMu sync.Mutex // serialises lifecycle operations
	// cfgMu serialises configuration writers. A writer that merges into the
	// live config and then fails validation used to leave memory and disk
	// disagreeing, and every later write failed with the same error.
	cfgMu sync.Mutex

	mu        sync.Mutex
	cfg       config.Config
	eng       *engine.Engine
	phase     state.Phase
	reason    string
	since     time.Time
	startedAt time.Time
	tunFD     int
	tunErr    string

	// providerFetched records when each proxy provider was last fetched in this
	// run, which is what the interval gate reads. The configuration has no field
	// for it (a provider is a document statement, not a schedule), so it lives
	// here: the first start of a run refetches every provider, exactly like the
	// refresh-on-start a subscription gets, and the interval keeps the rest of
	// the run quiet. Guarded by mu.
	providerFetched map[string]providerFetch

	ctx    context.Context
	cancel context.CancelFunc
	loops  sync.WaitGroup

	heartbeat  atomic.Int64 // unix nano
	restarts   atomic.Int64
	lastErrMu  sync.RWMutex
	lastErr    string
	failStreak atomic.Int64

	host      Host
	protector func(fd uintptr) error

	restartTimes []time.Time
}

// New loads the configuration at cfgPath and returns a stopped supervisor.
func New(cfgPath string, log *logx.Logger) (*Supervisor, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = logx.New(logx.ParseLevel(cfg.LogLevel), 1024)
	}
	s := &Supervisor{
		cfgPath:         cfgPath,
		log:             log,
		cfg:             cfg,
		phase:           state.PhaseStopped,
		since:           time.Now(),
		tunFD:           -1,
		reason:          "",
		providerFetched: make(map[string]providerFetch),
	}
	return s, nil
}

// SetHost installs the platform tunnel hooks. Must be called before Start.
func (s *Supervisor) SetHost(h Host) {
	s.mu.Lock()
	s.host = h
	s.mu.Unlock()
}

// SetProtector installs the socket protection hook (HarmonyOS: VpnConnection
// protect). Traffic created by the engine must bypass the tun.
func (s *Supervisor) SetProtector(fn func(fd uintptr) error) {
	s.mu.Lock()
	s.protector = fn
	s.mu.Unlock()
}

// Logger returns the supervisor's logger.
func (s *Supervisor) Logger() *logx.Logger { return s.log }

// Config returns a copy of the current configuration.
func (s *Supervisor) Config() config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Start brings the engine up. When tunFD < 0 the system tunnel is requested
// from the host; if that fails the engine still starts with the mixed inbound
// and reports "degraded" with the real reason.
func (s *Supervisor) Start(ctx context.Context, tunFD int) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	if s.phase == state.PhaseRunning || s.phase == state.PhaseDegraded || s.phase == state.PhaseStarting {
		s.mu.Unlock()
		return nil
	}
	cfg := s.cfg
	s.phase = state.PhaseStarting
	s.reason = ""
	s.since = time.Now()
	s.mu.Unlock()

	// The RPC context is short-lived (a UI request); the engine lives until
	// Stop. Detach it, or the tunnel would die when the RPC deadline expires —
	// exactly the kind of silent background death this supervisor exists to
	// prevent.
	life, lifeCancel := context.WithCancel(context.WithoutCancel(ctx))
	defer func() {
		if s.eng == nil {
			lifeCancel()
		}
	}()

	if tunFD < 3 {
		// 0 (the Go zero value callers pass) and 1/2 are stdio, not a tun fd.
		// Treating 0 as valid skips the tun_up handshake entirely and starts the
		// engine on stdin — the "tun up (fd 0)" failure that killed the host.
		tunFD = s.requestTun(life)
	}

	eng, err := engine.New(cfg, s.log)
	if err != nil {
		lifeCancel()
		s.fail("engine configuration: " + err.Error())
		return err
	}

	if err := eng.Start(life, tunFD); err != nil {
		lifeCancel()
		s.fail("engine start: " + err.Error())
		return err
	}

	s.mu.Lock()
	s.eng = eng
	s.tunFD = tunFD
	s.startedAt = time.Now()
	s.since = time.Now()
	s.mu.Unlock()

	s.log.Infof("engine started (tun fd %d, mode %s)", tunFD, cfg.Mode)

	switch {
	case tunFD < 0 && cfg.Tun.AutoRoute:
		s.degrade("tun unavailable: mixed proxy only")
	case func() bool { ok, total := eng.OutboundCount(); return total > 0 && ok == 0 }():
		s.degrade("no outbound could be built: " + eng.LastError())
	default:
		s.setPhase(state.PhaseRunning, "")
	}

	s.startLoops(life)
	return nil
}

// Stop shuts the engine down and tells the host to tear the tunnel down.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.stopLocked(ctx, true)
}

func (s *Supervisor) stopLocked(ctx context.Context, tearTun bool) error {
	s.mu.Lock()
	if s.phase == state.PhaseStopped || s.phase == state.PhaseStopping {
		s.mu.Unlock()
		return nil
	}
	eng := s.eng
	cancel := s.cancel
	s.phase = state.PhaseStopping
	s.since = time.Now()
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { s.loops.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		s.log.Warnf("supervisor loops did not stop in time")
	}

	if eng != nil {
		sctx, scancel := context.WithTimeout(ctx, 10*time.Second)
		if err := eng.Stop(sctx); err != nil {
			s.log.Warnf("engine stop: %v", err)
		}
		scancel()
	}
	s.mu.Lock()
	s.eng = nil
	s.tunFD = -1
	s.mu.Unlock()

	if tearTun && s.host != nil {
		hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
		if _, err := s.host.Request(hctx, "tun_down", nil); err != nil {
			s.log.Debugf("host tun_down: %v", err)
		}
		hcancel()
	}

	s.setPhase(state.PhaseStopped, "")
	s.log.Infof("supervisor stopped")
	return nil
}

// Restart replaces the engine with a freshly built one.
func (s *Supervisor) Restart(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	// Reuse the tun fd: the host keeps the device alive across engine restarts
	// so the VPN does not flap (and protect state stays valid).
	s.mu.Lock()
	fd := s.tunFD
	s.mu.Unlock()
	if err := s.stopLocked(ctx, false); err != nil {
		return err
	}
	return s.Start(ctx, fd)
}

// requestTun asks the host for a tun device.
func (s *Supervisor) requestTun(ctx context.Context) int {
	s.mu.Lock()
	h := s.host
	s.mu.Unlock()
	if h == nil {
		// Desktop/dev mode: there is no VPN extension to ask.
		return -1
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res, err := h.Request(cctx, "tun_up", map[string]any{
		"mtu":  s.cfg.Tun.MTU,
		"ipv4": s.cfg.Tun.IPv4,
		"ipv6": s.cfg.Tun.IPv6,
		"dns":  s.cfg.Tun.DNS,
	})
	if err != nil {
		s.log.Warnf("tun_up failed: %v", err)
		s.mu.Lock()
		s.tunErr = err.Error()
		s.mu.Unlock()
		return -1
	}
	fd := -1
	switch v := res["fd"].(type) {
	case float64:
		fd = int(v)
	case int:
		fd = v
	case json.Number:
		n, _ := v.Int64()
		fd = int(n)
	}
	if fd < 3 {
		// 0/1/2 are stdio: a tun fd must be a real descriptor or the engine
		// would end up polling stdin and the data path dies silently.
		s.log.Errorf("tun_up returned no usable fd (%v)", res)
		return -1
	}
	s.log.Infof("host created tun fd %d", fd)
	s.mu.Lock()
	s.tunErr = ""
	s.mu.Unlock()
	return fd
}

// tunReason reports why the tunnel is not attached.
func (s *Supervisor) tunReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunErr == "" {
		return "VPN 扩展进程尚未就绪"
	}
	return s.tunErr
}

// tryAttachTun retries the host hand-shake after a degraded start.
//
// This is the common cold-start race: the UI enables the VPN before the VPN
// extension has connected its host channel, so the first tun_up fails. Instead
// of leaving the user with "tun unavailable" until they toggle again, the
// watchdog keeps trying while the engine is otherwise healthy.
func (s *Supervisor) tryAttachTun() {
	s.mu.Lock()
	eng := s.eng
	host := s.host
	s.mu.Unlock()
	if eng == nil || host == nil || eng.TunUp() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fd := s.requestTun(ctx)
	if fd < 0 {
		return
	}
	if err := eng.AttachTun(fd, s.Config().Tun.MTU); err != nil {
		s.log.Warnf("attach tun: %v", err)
		s.mu.Lock()
		s.tunErr = err.Error()
		s.mu.Unlock()
		return
	}
	s.mu.Lock()
	s.tunFD = fd
	s.mu.Unlock()
	s.log.Infof("tun attached after retry (fd %d)", fd)
	s.setPhase(state.PhaseRunning, "")
}

// startLoops launches the heartbeat and the health watchdog.
// refreshDueSubscriptions refreshes the subscriptions and the proxy providers
// whose update interval has elapsed. It runs once per start rather than on a
// timer: a timer would wake a device that is otherwise idle, and starting the
// tunnel is exactly when a profile is expected to be current (Clash refreshes on
// launch too).
func (s *Supervisor) refreshDueSubscriptions(ctx context.Context) {
	s.mu.Lock()
	var due []string
	now := time.Now().Unix()
	for _, sub := range s.cfg.Subscriptions {
		if sub.Interval <= 0 || sub.URL == "" {
			continue
		}
		if sub.Updated+int64(sub.Interval) <= now {
			due = append(due, sub.Name)
		}
	}
	s.mu.Unlock()
	// Providers gate on the same "due" idea, but their last-fetch time lives in
	// this run's memory (see providerFetched), so only a provider whose interval
	// has really elapsed since the last fetch is downloaded again.
	providers := s.dueProviders(time.Now())
	if len(due) == 0 && len(providers) == 0 {
		return
	}
	s.loops.Add(1)
	go func() {
		defer s.loops.Done()
		for _, name := range due {
			if ctx.Err() != nil {
				return
			}
			if _, err := s.updateSubscription(ctx, name); err != nil {
				s.log.Warnf("scheduled refresh of subscription %s failed: %v", name, err)
				continue
			}
			s.log.Infof("scheduled refresh of subscription %s done", name)
		}
		// Providers after subscriptions: a subscription body can define the
		// providers it uses, and updateSubscription already fetched the ones it
		// changed, which this loop then finds no longer due.
		for _, name := range providers {
			if ctx.Err() != nil {
				return
			}
			if _, err := s.applyProvider(ctx, name); err != nil {
				s.log.Warnf("scheduled refresh of provider %s failed: %v", name, err)
				continue
			}
			s.log.Infof("scheduled refresh of provider %s done", name)
		}
	}()
}

func (s *Supervisor) startLoops(parent context.Context) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	ctx, cancel := context.WithCancel(parent)
	s.ctx, s.cancel = ctx, cancel
	s.mu.Unlock()

	s.heartbeat.Store(time.Now().UnixNano())
	s.refreshDueSubscriptions(ctx)
	s.loops.Add(2)
	go func() {
		defer s.loops.Done()
		// 5s cadence: still notices a wedged scheduler within ~15s, but the
		// idle engine wakes up 5x less often than the old 1s ticker (battery).
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.heartbeat.Store(time.Now().UnixNano())
			}
		}
	}()
	go func() {
		defer s.loops.Done()
		s.watchdog(ctx)
	}()
}

// watchdog notices stalls and dead engines. It is the only place that restarts
// the data path, so a restart can never race with itself.
func (s *Supervisor) watchdog(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	var badChecks int
	ticks := 0
	var lastLine string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ticks++
		s.mu.Lock()
		eng := s.eng
		phase := s.phase
		s.mu.Unlock()
		if ticks%12 == 0 { // every 60s one heartbeat line, plus on any real change
			st := s.Status()
			line := fmt.Sprintf("phase=%s conns=%d total=%d up=%d down=%d tun=%v dns=%v err=%q",
				st.Phase, st.Traffic.Active, st.Traffic.TotalConn, st.Traffic.Up, st.Traffic.Down,
				st.Tun.Up, st.DNS.Enabled, st.Reason)
			if line != lastLine {
				lastLine = line
				s.log.Infof("alive %s", line)
			}
		}
		if eng == nil || (phase != state.PhaseRunning && phase != state.PhaseDegraded) {
			continue
		}

		ok := true
		if !eng.Running() {
			s.setErr("engine reported not running")
			ok = false
		}
		// Probing opens a real connection to our own listener; do it every 30s
		// instead of every tick so the probe itself stays invisible in stats.
		if ticks%6 == 0 {
			if err := eng.ProbeInbound(); err != nil {
				s.setErr("inbound probe: " + err.Error())
				ok = false
			}
		}
		// The tun can disappear when the system tears the VPN down; that is a
		// degraded data path, not a reason to restart the engine.
		if s.Config().Tun.AutoRoute && !eng.TunUp() {
			if phase == state.PhaseRunning {
				s.degrade("tun detached")
			}
			s.tryAttachTun()
			continue
		}
		// A stalled heartbeat means the scheduler or a lock is wedged; that is
		// itself a failure, even if the engine object claims to be running.
		age := time.Since(time.Unix(0, s.heartbeat.Load()))
		if age > 20*time.Second {
			s.setErr(fmt.Sprintf("heartbeat stalled for %s", age.Round(time.Second)))
			ok = false
		}
		if ok {
			badChecks = 0
			if phase == state.PhaseDegraded && eng.TunUp() {
				s.setPhase(state.PhaseRunning, "")
			}
			continue
		}
		badChecks++
		if badChecks < 2 {
			continue
		}
		badChecks = 0
		s.log.Errorf("health check failed (%s), restarting engine", s.LastError())
		if err := s.restartFromWatchdog(); err != nil {
			s.log.Errorf("engine restart failed: %v", err)
		}
	}
}

func (s *Supervisor) restartFromWatchdog() error {
	// Never block the watchdog behind a user-initiated start/stop: if another
	// lifecycle operation holds the lock, that operation is already fixing the
	// state and the next tick can re-evaluate.
	if !s.opMu.TryLock() {
		return nil
	}
	defer s.opMu.Unlock()

	now := time.Now()
	kept := s.restartTimes[:0]
	for _, t := range s.restartTimes {
		if now.Sub(t) < 10*time.Minute {
			kept = append(kept, t)
		}
	}
	s.restartTimes = kept
	if len(s.restartTimes) >= 5 {
		s.fail("core keeps failing (5 restarts in 10 minutes); last error: " + s.LastError())
		return errors.New("restart budget exhausted")
	}
	s.restartTimes = append(s.restartTimes, now)
	s.restarts.Add(1)

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	fd := s.tunFD
	eng := s.eng
	s.mu.Unlock()

	// Detach the old engine and build a new one.
	if eng != nil {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = eng.DetachTun()
		if err := eng.Stop(sctx); err != nil {
			s.log.Warnf("old engine stop: %v", err)
		}
		cancel()
	}
	// DetachTun closed the old fd. Reusing it here would leave the new engine
	// reporting "tun up" while the descriptor is dead and the host still holds
	// a stale VpnConnection — every protect() and every packet then fails.
	// Destroy the host-side tun and ask for a fresh one so both sides agree.
	if s.host != nil {
		hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
		if _, herr := s.host.Request(hctx, "tun_down", nil); herr != nil {
			s.log.Debugf("host tun_down: %v", herr)
		}
		hcancel()
	}
	s.mu.Lock()
	s.tunFD = -1
	s.mu.Unlock()
	fd = s.requestTun(ctx)
	if fd < 0 {
		s.fail("tun reattach after restart failed: " + s.tunErr)
		return errors.New("tun reattach failed")
	}
	newEng, err := engine.New(s.Config(), s.log)
	if err != nil {
		s.fail("engine rebuild: " + err.Error())
		return err
	}
	if err := newEng.Start(ctx, fd); err != nil {
		s.fail("engine restart: " + err.Error())
		return err
	}
	s.mu.Lock()
	s.eng = newEng
	s.mu.Unlock()
	s.log.Infof("engine restarted (attempt %d)", s.restarts.Load())
	s.setPhase(state.PhaseRunning, "")
	return nil
}

// reload rebuilds outbounds/rules without touching the tun or listener.
func (s *Supervisor) reload() error {
	s.mu.Lock()
	eng := s.eng
	cfg := s.cfg
	s.mu.Unlock()
	if eng == nil {
		return nil
	}
	return eng.Reload(cfg)
}

// Status renders the complete, truthful state for the UI.
func (s *Supervisor) Status() state.Status {
	s.mu.Lock()
	phase := s.phase
	reason := s.reason
	since := s.since
	started := s.startedAt
	eng := s.eng
	tunFD := s.tunFD
	// The configured mode is the truthful value when no engine is running; the
	// engine's copy is only used below when it exists.
	cfgMode := s.cfg.Mode
	s.mu.Unlock()

	st := state.Status{
		// Never let a nil slice reach the UI as JSON null: ArkTS iterating
		// `null` throws a TypeError and takes the whole app down.
		Inbounds:  []state.InboundStatus{},
		Groups:    []state.GroupStatus{},
		Phase:     phase,
		Reason:    reason,
		SinceUnix: since.Unix(),
		Version:   version.Version,
		Health: state.Health{
			HeartbeatAgoMS: heartbeatAgeMS(s.heartbeat.Load()),
			Goroutines:     runtime.NumGoroutine(),
			OpenFDs:        countFDs(),
			Restarts:       int(s.restarts.Load()),
			LastError:      s.LastError(),
			StartedUnix:    unixOrZero(started),
		},
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	st.Health.HeapMB = float64(ms.HeapAlloc) / (1 << 20)

	if eng != nil {
		es := eng.Status()
		st.Mode = es.Mode
		st.Traffic = es.Traffic
		st.Inbounds = es.Inbounds
		st.DNS = es.DNS
		st.Tun = es.Tun
		st.UptimeSec = es.UptimeSec
		st.Groups = eng.Groups()
	} else {
		st.Tun = state.TunStatus{FD: tunFD}
		st.Mode = cfgMode
		st.Groups = s.Groups()
	}
	return st
}

// LastError returns the most recent failure, if any.
func (s *Supervisor) LastError() string {
	s.lastErrMu.RLock()
	defer s.lastErrMu.RUnlock()
	return s.lastErr
}

func (s *Supervisor) setErr(msg string) {
	s.lastErrMu.Lock()
	s.lastErr = msg
	s.lastErrMu.Unlock()
}

// heartbeatAgeMS reports how long ago the watchdog last ticked. A zero
// timestamp (engine never started) is reported as -1 instead of a 1970 delta.
func heartbeatAgeMS(ns int64) int64 {
	if ns <= 0 {
		return -1
	}
	return time.Since(time.Unix(0, ns)).Milliseconds()
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (s *Supervisor) setPhase(p state.Phase, reason string) {
	s.mu.Lock()
	if s.phase != p {
		s.since = time.Now()
	}
	s.phase = p
	s.reason = reason
	s.mu.Unlock()
}

func (s *Supervisor) degrade(reason string) {
	s.log.Warnf("degraded: %s", reason)
	s.setPhase(state.PhaseDegraded, reason)
}

func (s *Supervisor) fail(reason string) {
	s.setErr(reason)
	s.setPhase(state.PhaseFailed, reason)
	s.log.Errorf("failed: %s", reason)
}

// Call implements rpc.Handler.
var _ rpc.Handler = (*Supervisor)(nil)
