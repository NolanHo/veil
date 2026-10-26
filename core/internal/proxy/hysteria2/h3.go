package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2/hpack"
)

// Hysteria2 authentication is an HTTP/3 request, but the client only ever needs
// a tiny subset of HTTP/3: one POST with a handful of headers, and the status
// code of the reply. Rather than pull in a full HTTP/3 stack we speak the few
// frames involved directly on the QUIC connection. Only QPACK's static table is
// used (our SETTINGS advertise a dynamic-table capacity of 0, so conforming
// servers must not reference dynamic entries), which keeps the codec small.
const (
	frameData     = 0x00
	frameHeaders  = 0x01
	frameSettings = 0x04

	uniControl     = 0x00
	uniQpackEnc    = 0x02
	uniQpackDec    = 0x03
	maxHeaderBytes = 64 << 10
)

// h3State holds the long-lived unidirectional streams an HTTP/3 connection
// requires. They must stay open for the lifetime of the connection, so the
// client keeps references to them.
type h3State struct {
	ctrl *quic.SendStream
	enc  *quic.SendStream
	dec  *quic.SendStream
}

// headerField is one QPACK-decoded header.
type headerField struct {
	name  string
	value string
}

// qpackStaticTable is the QPACK static table (RFC 9204 Appendix A).
var qpackStaticTable = []headerField{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

// staticIndex finds an exact name/value match in the static table.
func staticIndex(name, value string) int {
	for i, f := range qpackStaticTable {
		if f.name == name && f.value == value {
			return i
		}
	}
	return -1
}

// staticNameIndex finds the first static entry with the given name.
func staticNameIndex(name string) int {
	for i, f := range qpackStaticTable {
		if f.name == name {
			return i
		}
	}
	return -1
}

// appendQPACKInt appends an integer with an n-bit prefix (RFC 7541 §5.1).
func appendQPACKInt(dst []byte, v uint64, prefix uint8, first byte) []byte {
	max := uint64(1)<<prefix - 1
	if v < max {
		return append(dst, first|byte(v))
	}
	dst = append(dst, first|byte(max))
	v -= max
	for v >= 128 {
		dst = append(dst, byte(v%128)|0x80)
		v /= 128
	}
	return append(dst, byte(v))
}

// appendQPACKString appends a plain (not Huffman-coded) string literal.
func appendQPACKString(dst []byte, s string) []byte {
	dst = appendQPACKInt(dst, uint64(len(s)), 7, 0)
	return append(dst, s...)
}

// encodeFieldSection encodes headers using only the static table: exact matches
// become indexed field lines, known names become name references and everything
// else becomes a literal name.
func encodeFieldSection(fields []headerField) []byte {
	// RFC 9204 §4.5.1: every field section starts with the Encoded Field Section
	// Prefix. Without a dynamic table Required Insert Count is 0, and the Delta
	// Base equals it, so the prefix is the two bytes 0x00 0x00. Omitting it made
	// a real server read our first field line as the prefix and answer
	// QPACK_DECOMPRESSION_FAILED (HTTP/3 stream error 0x200).
	out := []byte{0x00, 0x00}
	for _, f := range fields {
		// HTTP/3 field names are lowercase on the wire; a real server rejects an
		// uppercase one with H3_MESSAGE_ERROR (0x10e). hysteria's canonical
		// spelling ("Hysteria-Auth") is only used inside this package, so
		// normalise here instead of at every call site.
		f.name = strings.ToLower(f.name)
		if i := staticIndex(f.name, f.value); i >= 0 {
			out = appendQPACKInt(out, uint64(i), 6, 0xC0) // 1 1 index(6+)
			continue
		}
		if i := staticNameIndex(f.name); i >= 0 {
			// 0 1 N T nameIndex(4+), T=1 (static)
			out = appendQPACKInt(out, uint64(i), 4, 0x50)
			out = appendQPACKString(out, f.value)
			continue
		}
		// 0 0 1 N H nameLen(3+) name value
		out = appendQPACKInt(out, uint64(len(f.name)), 3, 0x20)
		out = append(out, f.name...)
		out = appendQPACKString(out, f.value)
	}
	return out
}

// readQPACKInt reads an integer with an n-bit prefix.
func readQPACKInt(b []byte, prefix uint8) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	max := uint64(1)<<prefix - 1
	v := uint64(b[0]) & max
	if v < max {
		return v, 1, nil
	}
	var shift uint
	for i := 1; i < len(b); i++ {
		c := b[i]
		v += uint64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
		if shift > 62 {
			return 0, 0, errors.New("hysteria2: qpack integer overflow")
		}
	}
	return 0, 0, io.ErrUnexpectedEOF
}

// readQPACKString reads a string literal, Huffman-decoding it when needed.
func readQPACKString(b []byte) (string, int, error) {
	if len(b) == 0 {
		return "", 0, io.ErrUnexpectedEOF
	}
	huffman := b[0]&0x80 != 0
	length, n, err := readQPACKInt(b, 7)
	if err != nil {
		return "", 0, err
	}
	if uint64(len(b)-n) < length {
		return "", 0, io.ErrUnexpectedEOF
	}
	raw := b[n : n+int(length)]
	if !huffman {
		return string(raw), n + int(length), nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", 0, fmt.Errorf("hysteria2: bad huffman string: %w", err)
	}
	return s, n + int(length), nil
}

// decodeFieldSection decodes a QPACK field section that uses the static table.
// Dynamic-table references are rejected: we advertise a capacity of zero, so a
// conforming server never emits them.
func decodeFieldSection(b []byte) ([]headerField, error) {
	// RFC 9204 §4.5.1: the Encoded Field Section Prefix comes first — Encoded
	// Required Insert Count (8-bit prefix) then Delta Base (7-bit prefix and
	// sign) — and has to be consumed before the field lines. With no dynamic
	// table it is 0x00 0x00; without consuming it the first field line looked
	// like a prefix and the prefix looked like "unsupported qpack
	// representation 0x00".
	insertCount, n, err := readQPACKInt(b, 8)
	if err != nil {
		return nil, err
	}
	if insertCount != 0 {
		// openH3Streams advertises a dynamic-table capacity of 0, so the only
		// Encoded Required Insert Count a conforming peer may send is 0.
		return nil, fmt.Errorf("hysteria2: qpack required insert count %d with an empty dynamic table", insertCount)
	}
	b = b[n:]
	if _, n, err = readQPACKInt(b, 7); err != nil {
		return nil, err
	}
	b = b[n:]

	var out []headerField
	for len(b) > 0 {
		first := b[0]
		switch {
		case first&0x80 != 0: // 1 T index(6+)
			idx, n, err := readQPACKInt(b, 6)
			if err != nil {
				return nil, err
			}
			if first&0x40 == 0 {
				return nil, errors.New("hysteria2: dynamic qpack reference is not supported")
			}
			if idx >= uint64(len(qpackStaticTable)) {
				return nil, fmt.Errorf("hysteria2: qpack static index %d out of range", idx)
			}
			out = append(out, qpackStaticTable[idx])
			b = b[n:]
		case first&0xC0 == 0x40: // 0 1 N T index(4+)
			idx, n, err := readQPACKInt(b, 4)
			if err != nil {
				return nil, err
			}
			if first&0x10 == 0 {
				return nil, errors.New("hysteria2: dynamic qpack reference is not supported")
			}
			if idx >= uint64(len(qpackStaticTable)) {
				return nil, fmt.Errorf("hysteria2: qpack static index %d out of range", idx)
			}
			value, m, err := readQPACKString(b[n:])
			if err != nil {
				return nil, err
			}
			out = append(out, headerField{name: qpackStaticTable[idx].name, value: value})
			b = b[n+m:]
		case first&0xE0 == 0x20: // 0 0 1 N H nameLen(3+)
			nameLen, n, err := readQPACKInt(b, 3)
			if err != nil {
				return nil, err
			}
			if uint64(len(b)-n) < nameLen {
				return nil, io.ErrUnexpectedEOF
			}
			name := string(b[n : n+int(nameLen)])
			if first&0x08 != 0 {
				name, err = hpack.HuffmanDecodeToString(b[n : n+int(nameLen)])
				if err != nil {
					return nil, err
				}
			}
			value, m, err := readQPACKString(b[n+int(nameLen):])
			if err != nil {
				return nil, err
			}
			out = append(out, headerField{name: name, value: value})
			b = b[n+int(nameLen)+m:]
		default:
			return nil, fmt.Errorf("hysteria2: unsupported qpack representation 0x%02x", first)
		}
	}
	return out, nil
}

// openH3Streams opens the unidirectional streams HTTP/3 requires, sending an
// empty SETTINGS frame (which implies a QPACK dynamic-table capacity of 0).
func openH3Streams(ctx context.Context, conn *quic.Conn) (*h3State, error) {
	ctrl, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	msg := quicvarint.Append(nil, uniControl)
	msg = quicvarint.Append(msg, frameSettings)
	msg = quicvarint.Append(msg, 0)
	if _, err := ctrl.Write(msg); err != nil {
		return nil, err
	}
	state := &h3State{ctrl: ctrl}
	if state.enc, err = openTypedUniStream(ctx, conn, uniQpackEnc); err != nil {
		return nil, err
	}
	if state.dec, err = openTypedUniStream(ctx, conn, uniQpackDec); err != nil {
		return nil, err
	}
	return state, nil
}

func openTypedUniStream(ctx context.Context, conn *quic.Conn, streamType uint64) (*quic.SendStream, error) {
	str, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := str.Write(quicvarint.Append(nil, streamType)); err != nil {
		return nil, err
	}
	return str, nil
}

// h3Request sends one HTTP/3 request without a body and returns the decoded
// response headers.
func h3Request(ctx context.Context, conn *quic.Conn, authority, path string, headers []headerField) ([]headerField, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	fields := []headerField{
		{":method", "POST"},
		{":scheme", "https"},
		{":authority", authority},
		{":path", path},
	}
	fields = append(fields, headers...)
	block := encodeFieldSection(fields)

	frame := quicvarint.Append(nil, frameHeaders)
	frame = quicvarint.Append(frame, uint64(len(block)))
	frame = append(frame, block...)
	if _, err := stream.Write(frame); err != nil {
		return nil, err
	}
	// No request body: half-close so the server knows the request is complete.
	if err := stream.Close(); err != nil {
		return nil, err
	}
	return readH3ResponseHeaders(stream)
}

func readH3ResponseHeaders(stream io.Reader) ([]headerField, error) {
	vr := quicvarint.NewReader(stream)
	for {
		frameType, err := quicvarint.Read(vr)
		if err != nil {
			return nil, fmt.Errorf("hysteria2: read h3 frame: %w", err)
		}
		length, err := quicvarint.Read(vr)
		if err != nil {
			return nil, fmt.Errorf("hysteria2: read h3 frame length: %w", err)
		}
		// Frames other than HEADERS are skipped; a huge length is a protocol
		// error rather than something to allocate for.
		if length > maxHeaderBytes {
			return nil, fmt.Errorf("hysteria2: h3 frame too large (%d)", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return nil, fmt.Errorf("hysteria2: read h3 frame payload: %w", err)
		}
		if frameType != frameHeaders {
			continue
		}
		fields, err := decodeFieldSection(payload)
		if err != nil {
			return nil, err
		}
		for _, f := range fields {
			if f.name == ":status" {
				return fields, nil
			}
		}
		return nil, errors.New("hysteria2: response has no :status")
	}
}

// statusOf extracts the :status pseudo-header.
func statusOf(fields []headerField) (int, error) {
	for _, f := range fields {
		if f.name == ":status" {
			code, err := strconv.Atoi(f.value)
			if err != nil {
				return 0, fmt.Errorf("hysteria2: bad status %q", f.value)
			}
			return code, nil
		}
	}
	return 0, errors.New("hysteria2: response has no :status")
}

// headerValue returns the first value of name, or "".
//
// The comparison ignores case: decoded field names are lowercase (HTTP/3
// requires it), while the constants in this package keep hysteria's canonical
// spelling ("Hysteria-UDP"). A case-sensitive lookup silently missed the
// server's reply about UDP relaying.
func headerValue(fields []headerField, name string) string {
	for _, f := range fields {
		if strings.EqualFold(f.name, name) {
			return f.value
		}
	}
	return ""
}
