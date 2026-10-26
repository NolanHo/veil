package hysteria2

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/blake2b"
)

const (
	// salamanderSaltLen is the clear prefix every packet carries; the per-packet
	// keystream is derived from it.
	salamanderSaltLen = 8
	// salamanderMinPassword matches the reference implementation, which refuses
	// obfuscation passwords shorter than four bytes.
	salamanderMinPassword = 4
	// salamanderBufSize is the largest datagram handled: QUIC packets stay below
	// 1500 bytes, and the reference wrapper also uses 2 KiB.
	salamanderBufSize = 2048
)

// salamander is Hysteria2's salamander obfuscation. Every datagram on the wire
// is [8-byte random salt][payload XOR keystream] with
// keystream = BLAKE2b-256(password || salt), the 32-byte digest repeated once
// the payload is longer than a block.
//
// This is the reference construction used by both the Hysteria2 client and
// server (apernet/hysteria, extras/obfs/salamander.go): BLAKE2b is unkeyed
// there, the password is the input prefix and the salt is appended to it.
// TestSalamanderKnownAnswerVector pins the bytes against a packet produced by
// the reference implementation.
type salamander struct {
	password []byte
	// keyInput is the password||salt scratch buffer: a read and a write
	// direction obfuscate concurrently, so it needs a lock to stay allocation
	// free per packet.
	keyInput []byte
	mu       sync.Mutex
}

func newSalamander(password string) (*salamander, error) {
	if len(password) < salamanderMinPassword {
		return nil, fmt.Errorf("salamander: obfs password must be at least %d bytes", salamanderMinPassword)
	}
	pw := []byte(password)
	return &salamander{password: pw, keyInput: make([]byte, len(pw)+salamanderSaltLen)}, nil
}

// obfuscate writes salt||ciphertext into out and returns that slice.
func (o *salamander) obfuscate(in, out []byte) ([]byte, error) {
	out = out[:len(in)+salamanderSaltLen]
	if _, err := randRead(out[:salamanderSaltLen]); err != nil {
		return nil, err
	}
	return o.seal(in, out), nil
}

// seal obfuscates in into out using the salt already stored in out[:8]. It
// exists so a test can feed a known salt.
func (o *salamander) seal(in, out []byte) []byte {
	key := o.key(out[:salamanderSaltLen])
	for i, c := range in {
		out[salamanderSaltLen+i] = c ^ key[i%len(key)]
	}
	return out[:len(in)+salamanderSaltLen]
}

// deobfuscate writes the payload of in into out and returns it, or nil when in
// cannot be an obfuscated packet (too short, or out too small).
func (o *salamander) deobfuscate(in, out []byte) []byte {
	if len(in) <= salamanderSaltLen {
		return nil
	}
	payload := len(in) - salamanderSaltLen
	if len(out) < payload {
		return nil
	}
	key := o.key(in[:salamanderSaltLen])
	for i, c := range in[salamanderSaltLen:] {
		out[i] = c ^ key[i%len(key)]
	}
	return out[:payload]
}

func (o *salamander) key(salt []byte) [blake2b.Size256]byte {
	o.mu.Lock()
	copy(o.keyInput, o.password)
	copy(o.keyInput[len(o.password):], salt)
	sum := blake2b.Sum256(o.keyInput)
	o.mu.Unlock()
	return sum
}

// salamanderConn applies salamander obfuscation to a datagram connection. The
// lengths reported to the caller are payload lengths; the wire packet is always
// salamanderSaltLen bytes longer.
type salamanderConn struct {
	conn net.PacketConn
	obfs *salamander

	readBuf  []byte
	readMu   sync.Mutex
	writeBuf []byte
	writeMu  sync.Mutex
}

// udpLikeConn is the UDP-specific surface quic-go uses to size socket buffers
// and to manage path-MTU discovery. Forwarding it keeps those optimizations
// when obfuscation wraps the socket, which is what the reference wrapper does.
type udpLikeConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func newSalamanderConn(conn net.PacketConn, obfs *salamander) net.PacketConn {
	c := &salamanderConn{
		conn:     conn,
		obfs:     obfs,
		readBuf:  make([]byte, salamanderBufSize),
		writeBuf: make([]byte, salamanderBufSize),
	}
	if udp, ok := conn.(udpLikeConn); ok {
		return &salamanderUDPConn{salamanderConn: c, udp: udp}
	}
	return c
}

type salamanderUDPConn struct {
	*salamanderConn
	udp udpLikeConn
}

func (c *salamanderUDPConn) SyscallConn() (syscall.RawConn, error) { return c.udp.SyscallConn() }
func (c *salamanderUDPConn) SetReadBuffer(n int) error             { return c.udp.SetReadBuffer(n) }
func (c *salamanderUDPConn) SetWriteBuffer(n int) error            { return c.udp.SetWriteBuffer(n) }

func (c *salamanderConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.readMu.Lock()
		n, addr, err := c.conn.ReadFrom(c.readBuf)
		if n <= 0 {
			c.readMu.Unlock()
			return n, addr, err
		}
		// Anything that cannot be an obfuscated datagram is dropped and the next
		// one is read: a junk packet (port scan, stray probe) must not surface as
		// a QUIC packet.
		payload := c.obfs.deobfuscate(c.readBuf[:n], p)
		c.readMu.Unlock()
		if payload != nil {
			return len(payload), addr, nil
		}
		if err != nil {
			return 0, addr, err
		}
	}
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire, err := c.obfs.obfuscate(p, c.writeBuf)
	if err != nil {
		return 0, err
	}
	if _, err := c.conn.WriteTo(wire, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *salamanderConn) Close() error                      { return c.conn.Close() }
func (c *salamanderConn) LocalAddr() net.Addr               { return c.conn.LocalAddr() }
func (c *salamanderConn) SetDeadline(t time.Time) error     { return c.conn.SetDeadline(t) }
func (c *salamanderConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

func (c *salamanderConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
