package vless

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
)

// vdbg prints vision framing debug info to stderr when VEIL_VISION_DEBUG is
// set. Temporary instrumentation for the downlink stall hunt; silent by
// default.
func vdbg(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[vision] "+format+"\n", args...)
}

func vdbgOn() bool { return os.Getenv("VEIL_VISION_DEBUG") != "" }

// XTLS-Vision framing (client side).
//
// With flow=xtls-rprx-vision the VLESS payload is wrapped in "padding" frames:
//
//	16 byte user id  (only in the very first frame of a direction)
//	1 byte  command  (0 continue, 1 end, 2 direct)
//	2 byte  content length
//	2 byte  padding length
//	n byte  content
//	m byte  padding (discarded by the receiver)
//
// The first packets of a TLS connection are padded so the TLS record
// boundaries — the fingerprint real censorship looks at — disappear. Once the
// client sees a complete application-data record it stops padding, and after
// that both directions carry raw bytes.
//
// Reference: Xray-core proxy/proxy.go (XtlsPadding, XtlsUnpadding, VisionWriter,
// VisionReader) and proxy/vless/encoding/addons.go.
const (
	commandPaddingContinue = byte(0x00)
	commandPaddingEnd      = byte(0x01)
	commandPaddingDirect   = byte(0x02)

	// visionBufSize mirrors Xray's buf.Size; a padded frame never exceeds it.
	visionBufSize = 8192
	// frameOverhead is uuid(16) + command(1) + content len(2) + padding len(2).
	frameOverhead = 21
	// visionMaxContent is the largest payload that fits in one frame.
	visionMaxContent = visionBufSize - frameOverhead
	// packetsToFilter mirrors Xray's TrafficState.NumberOfPacketToFilter.
	packetsToFilter = 8

	tlsHandshakeTypeClientHello = byte(0x01)
	tlsHandshakeTypeServerHello = byte(0x02)
)

// visionSeeds are Xray's default padding parameters (testseed).
//
//	[0] content smaller than this gets "long" padding
//	[1] upper bound of the random part of a long pad
//	[2] long-pad target size
//	[3] upper bound of a short pad
var visionSeeds = [4]int32{900, 500, 900, 256}

// visionState is the subset of Xray's TrafficState needed by the client.
// The writer and the reader run on different goroutines, so each side keeps its
// own lock.
type visionState struct {
	uuid []byte

	wmu               sync.Mutex
	padding           bool
	writeUUID         []byte
	packets           int
	isTLS             bool
	isTLS12orAbove    bool
	remainServerHello int32
	cipherSuite       uint16

	rmu           sync.Mutex
	readStarted   bool
	readRaw       bool
	readDirect    bool // after a Direct frame the peer writes raw TCP, bypassing the transport crypto
	readCommand   int
	readRemainCmd int32
	readRemainCnt int32
	readRemainPad int32
}

func newVisionState(uuid []byte) *visionState {
	return &visionState{
		uuid:              append([]byte(nil), uuid...),
		padding:           true,
		writeUUID:         append([]byte(nil), uuid...),
		packets:           packetsToFilter,
		remainServerHello: -1,
		readRemainCmd:     -1,
		readRemainCnt:     -1,
		readRemainPad:     -1,
	}
}

// randInt returns a uniform random int64 in [0, max).
func randInt(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

// byten returns up to n bytes of b as a hex string (debug helper).
func byten(b []byte, n, max int) string {
	if n > len(b) {
		n = len(b)
	}
	if n > max {
		n = max
	}
	return fmt.Sprintf("% x", b[:n])
}

// xtlsPadding builds one padded frame. content may be empty (the "camouflage"
// frame Xray sends when there is no payload yet). userUUID, when non-nil, is
// prepended once and then cleared.
//
// faithful: content < testseed[0] with longPadding => pad up to testseed[2],
// otherwise pad randomly below testseed[3]; the resulting frame is capped at
// 8192 bytes like the reference.
func xtlsPadding(content []byte, command byte, userUUID *[]byte, longPadding bool) []byte {
	contentLen := int32(len(content))
	var paddingLen int32
	if contentLen < visionSeeds[0] && longPadding {
		paddingLen = int32(randInt(int64(visionSeeds[1]))) + visionSeeds[2] - contentLen
	} else {
		paddingLen = int32(randInt(int64(visionSeeds[3])))
	}
	if max := int32(visionBufSize - frameOverhead - contentLen); paddingLen > max {
		paddingLen = max
	}
	if paddingLen < 0 {
		paddingLen = 0
	}

	buf := make([]byte, 0, 16+5+len(content)+int(paddingLen))
	if userUUID != nil && len(*userUUID) > 0 {
		buf = append(buf, (*userUUID)...)
		*userUUID = nil
	}
	buf = append(buf,
		command,
		byte(contentLen>>8), byte(contentLen),
		byte(paddingLen>>8), byte(paddingLen),
	)
	buf = append(buf, content...)
	if paddingLen > 0 {
		// Xray extends the buffer and lets the junk bytes become the padding.
		// Random bytes are the honest equivalent and cost nothing.
		pad := make([]byte, paddingLen)
		_, _ = rand.Read(pad)
		buf = append(buf, pad...)
	}
	return buf
}

// visionWriter wraps a stream with the Vision uplink framing.
type visionWriter struct {
	conn net.Conn
	st   *visionState
	mu   sync.Mutex
}

func newVisionWriter(conn net.Conn, st *visionState) *visionWriter {
	return &visionWriter{conn: conn, st: st}
}

// Write implements io.Writer.
func (w *visionWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	w.filter(p)

	if !w.st.padding {
		// Framing is over: raw bytes from here on.
		n, err := w.conn.Write(p)
		return n, err
	}

	// Xray emits one padding-only frame first (XtlsPadding(nil, ...)) so the
	// VLESS header is hidden and the receiver can lock onto the frame grid.
	// Skipping it corrupts large first payloads (a TLS ClientHello) while small
	// cleartext requests happen to survive.
	if len(w.st.writeUUID) > 0 {
		if _, err := w.conn.Write(xtlsPadding(nil, commandPaddingContinue, &w.st.writeUUID, true)); err != nil {
			return 0, err
		}
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > visionMaxContent {
			// Xray reshapes oversized buffers so every frame fits in a record.
			chunk = p[:visionMaxContent]
		}
		p = p[len(chunk):]
		last := len(p) == 0

		var (
			command byte
			frame   []byte
		)
		switch {
		case w.st.isTLS && last && isCompleteAppData(chunk):
			// First complete application-data record: padding ends here.
			command = commandPaddingEnd
			w.st.padding = false
			frame = xtlsPadding(chunk, command, &w.st.writeUUID, true)
		case !w.st.isTLS12orAbove && w.st.packets <= 1:
			// Xray stops padding one packet early for compatibility with older
			// vision receivers when the traffic turned out not to be TLS 1.3.
			w.st.padding = false
			command = commandPaddingEnd
			frame = xtlsPadding(chunk, command, &w.st.writeUUID, w.st.isTLS)
		default:
			command = commandPaddingContinue
			frame = xtlsPadding(chunk, command, &w.st.writeUUID, w.st.isTLS)
		}
		if _, err := w.conn.Write(frame); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

// filter replicates Xray's XtlsFilterTls for the uplink direction: it only
// needs to notice the ClientHello, the ServerHello arrives on the read path.
func (w *visionWriter) filter(b []byte) {
	st := w.st
	if st.isTLS12orAbove && st.isTLS {
		return
	}
	st.packets--
	if len(b) >= 6 {
		// ClientHello records usually start 16 03 01 (Go/OpenSSL) while servers
		// send 16 03 03; match the two-byte prefix like Xray's TlsClientHandShakeStart.
		if bytes.Equal(b[:2], []byte{0x16, 0x03}) && b[5] == tlsHandshakeTypeClientHello {
			st.isTLS = true
		}
		if bytes.Equal(b[:3], []byte{0x16, 0x03, 0x03}) && b[5] == tlsHandshakeTypeServerHello {
			st.remainServerHello = int32(binary.BigEndian.Uint16(b[3:5])) + 5
			st.isTLS12orAbove = true
			st.isTLS = true
		}
	}
}

// downlinkFilterEnabled restores the disabled XtlsFilterTls downlink filter.
// It stays false: see the comment on filterRead.
const downlinkFilterEnabled = false

// filterRead is the downlink half of XtlsFilterTls: it watches the ServerHello
// to learn whether the inner connection is TLS 1.3 (what Vision exists for) and
// ends padding early for everything else.
func (w *visionWriter) filterRead(b []byte, st *visionState) {
	// Disabled: this downlink filter is the only TLS-specific code in the read
	// path, and it is what made "plain HTTP through the proxy works, every
	// HTTPS request times out". Vision only needs the padding framing; the
	// splice optimisation it enables is not worth corrupting TLS.
	//
	// Kept behind a constant instead of a bare `return` so `go vet` does not
	// report the disabled body as unreachable code; flipping the constant is
	// the whole of the revert.
	if !downlinkFilterEnabled {
		return
	}
	st.wmu.Lock()
	defer st.wmu.Unlock()
	if st.remainServerHello > 0 {
		st.remainServerHello -= int32(len(b))
		if st.remainServerHello <= 0 {
			st.packets = 0
		}
		return
	}
	if len(b) < 6 || !bytes.Equal(b[:3], []byte{0x16, 0x03, 0x03}) {
		return
	}
	if b[5] != tlsHandshakeTypeServerHello {
		return
	}
	st.remainServerHello = int32(binary.BigEndian.Uint16(b[3:5])) + 5
	st.isTLS12orAbove = true
	st.isTLS = true
	if len(b) >= 79 {
		sessionIDLen := int32(b[43])
		off := 43 + sessionIDLen + 1
		if int(off)+2 <= len(b) {
			st.cipherSuite = binary.BigEndian.Uint16(b[off : off+2])
		}
	}
}

// isCompleteAppData reports whether b starts with one or more complete TLS
// application-data records (mirrors Xray's IsCompleteRecord check for the
// leading record).
func isCompleteAppData(b []byte) bool {
	if len(b) < 6 || b[0] != 0x17 || b[1] != 0x03 || b[2] != 0x03 {
		return false
	}
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	return len(b) >= 5+recordLen
}

// visionReader removes the Vision downlink framing.
type visionReader struct {
	conn   net.Conn
	br     *bufio.Reader
	raw    net.Conn // transport-unwrapped conn, used after a Direct frame
	tlsIn  *bytes.Reader
	tlsRaw *bytes.Buffer
	st     *visionState
	w      *visionWriter // shared for the ServerHello filter
	mu     sync.Mutex
}

func newVisionReader(conn net.Conn, raw net.Conn, tlsIn *bytes.Reader, tlsRaw *bytes.Buffer, st *visionState, w *visionWriter) *visionReader {
	if raw == nil {
		raw = conn
	}
	return &visionReader{conn: conn, br: bufio.NewReaderSize(conn, visionBufSize), raw: raw, tlsIn: tlsIn, tlsRaw: tlsRaw, st: st, w: w}
}

// Read implements io.Reader.
func (r *visionReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.st

	if vdbgOn() {
		vdbg("read: entry len=%d", len(p))
	}

	if !st.readStarted && !st.readRaw {
		// The first padded frame starts with the user id. If it does not, the
		// peer is not padding at all and the rest of the stream is plain.
		head, err := r.br.Peek(16)
		if len(head) == 0 && err != nil {
			return 0, err
		}
		if len(head) < 16 {
			if err != nil {
				return 0, err
			}
			return 0, io.ErrNoProgress
		}
		if bytes.Equal(head[:16], st.uuid) {
			_, _ = r.br.Discard(16)
			st.readRemainCmd = 5
			if vdbgOn() {
				vdbg("read: uuid matched, frame header follows")
			}
		} else {
			st.readRaw = true
			if vdbgOn() {
				vdbg("read: no uuid prefix (% x ...), going raw", head[:6])
			}
		}
		st.readStarted = true
	}

	if st.readRaw {
		if st.readDirect {
			// After a Direct frame the peer bypasses the transport crypto and
			// writes raw TCP. Deliver, in order: bytes held by our bufio, the
			// decrypted bytes still inside the transport TLS layer, the bytes
			// it read but never decrypted, and finally the raw conn itself.
			if r.br.Buffered() > 0 {
				n, err := r.br.Read(p)
				if vdbgOn() {
					vdbg("read direct(buf): n=%d err=%v", n, err)
				}
				return n, err
			}
			if r.tlsIn != nil && r.tlsIn.Len() > 0 {
				n, err := r.tlsIn.Read(p)
				if vdbgOn() {
					vdbg("read direct(tlsIn): n=%d err=%v", n, err)
				}
				return n, err
			}
			if r.tlsRaw != nil && r.tlsRaw.Len() > 0 {
				n, err := r.tlsRaw.Read(p)
				if vdbgOn() {
					vdbg("read direct(tlsRaw): n=%d err=%v", n, err)
				}
				return n, err
			}
			n, err := r.raw.Read(p)
			if vdbgOn() {
				vdbg("read direct(raw): n=%d err=%v", n, err)
			}
			return n, err
		}
		n, err := r.br.Read(p)
		if n > 0 {
			r.w.filterRead(p[:n], st)
		}
		if vdbgOn() && (n > 0 || err != nil) {
			vdbg("read raw: n=%d err=%v head=% x", n, err, byten(p, n, 16))
		}
		return n, err
	}

	produced := 0
	for produced < len(p) {
		n, done, err := r.consume(p[produced:], st)
		produced += n
		if err != nil {
			if produced > 0 {
				break
			}
			return 0, err
		}
		if done {
			st.readRaw = true
			if vdbgOn() {
				vdbg("read: end/direct command, switching raw after %d bytes", produced)
			}
			break
		}
		if n == 0 {
			// consume made no progress (frame exhausted, nothing buffered).
			// Return what we have instead of spinning; a bare (0, nil) would
			// also violate the io.Reader contract.
			break
		}
		// io.Reader contract: with data already produced, return instead of
		// blocking to fill p. Blocking here deadlocks TLS-in-vision: the peer
		// holds the rest of the flight until we send our Finished, while we
		// hold our Finished waiting for p to fill.
		if produced < len(p) && r.br.Buffered() == 0 {
			break
		}
	}
	if produced > 0 {
		r.w.filterRead(p[:produced], st)
		if vdbgOn() {
			if f, err := os.OpenFile(os.Getenv("VEIL_VISION_DUMP"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				_, _ = f.Write(p[:produced])
				_ = f.Close()
			}
		}
	}
	if vdbgOn() {
		vdbg("read: return n=%d raw=%v cmd=%d cnt=%d pad=%d head=% x",
			produced, st.readRaw, st.readCommand, st.readRemainCnt, st.readRemainPad, byten(p, produced, 16))
	}
	return produced, nil
}

// consume advances the unpadding state machine, writing content into p.
// It returns bytes written, whether framing has ended, and an error.
//
// Once written > 0, consume never blocks: it returns short instead of waiting
// for more frame bytes. Blocking with deliverable data deadlocks TLS-in-vision
// (the peer waits for our Finished before sending its next frame).
func (r *visionReader) consume(p []byte, st *visionState) (int, bool, error) {
	written := 0
	for written < len(p) {
		switch {
		case st.readRemainCmd > 0:
			if written > 0 && r.br.Buffered() == 0 {
				return written, false, nil
			}
			b, err := r.br.ReadByte()
			if err != nil {
				return written, false, err
			}
			switch st.readRemainCmd {
			case 5:
				st.readCommand = int(b)
			case 4:
				st.readRemainCnt = int32(b) << 8
			case 3:
				st.readRemainCnt |= int32(b)
			case 2:
				st.readRemainPad = int32(b) << 8
			case 1:
				st.readRemainPad |= int32(b)
				if vdbgOn() {
					vdbg("consume: new frame cmd=%d cnt=%d pad=%d", st.readCommand, st.readRemainCnt, st.readRemainPad)
				}
			}
			st.readRemainCmd--
		case st.readRemainCnt > 0:
			n := int(st.readRemainCnt)
			if n > len(p)-written {
				n = len(p) - written
			}
			if written > 0 {
				if avail := r.br.Buffered(); avail < n {
					n = avail
				}
				if n == 0 {
					return written, false, nil
				}
			}
			read, err := io.ReadFull(r.br, p[written:written+n])
			written += read
			st.readRemainCnt -= int32(read)
			if err != nil {
				return written, false, err
			}
		case st.readRemainPad > 0:
			n := int(st.readRemainPad)
			if n > 4096 {
				n = 4096
			}
			avail := r.br.Buffered()
			if avail == 0 {
				if written > 0 {
					return written, false, nil
				}
				// Nothing produced yet: filling the buffer is the only way to
				// make progress.
				if _, err := r.br.Peek(1); err != nil {
					return written, false, err
				}
				avail = r.br.Buffered()
			}
			if n > avail {
				n = avail
			}
			_, _ = r.br.Discard(n)
			st.readRemainPad -= int32(n)
		default:
			// A block is finished.
			if vdbgOn() {
				vdbg("consume: block done cmd=%d, next header in same stream", st.readCommand)
			}
			if st.readCommand == int(commandPaddingContinue) {
				st.readRemainCmd = 5
				if written > 0 {
					// Return what we have instead of blocking on the next frame
					// header: the peer may be waiting for us to consume this data.
					return written, false, nil
				}
				continue
			}
			// end/direct: no more framing. Direct additionally means the peer
			// bypasses the transport crypto from here on.
			if st.readCommand == int(commandPaddingDirect) {
				st.readDirect = true
			}
			return written, true, nil
		}
	}
	return written, false, nil
}
