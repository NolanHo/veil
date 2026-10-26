package wireguard

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"veil/internal/transport"
)

// parkPeerSocket installs a protector that stops the first socket the client
// creates and reports when it is parked.
//
// The client opens exactly one peer socket, and it opens it inside the bring-up.
// Parking there puts the first dial in the window this file is about: the device
// exists, the peer socket exists, and the client has not handed anything out
// yet. release (and the cleanup) unblocks it.
func parkPeerSocket(t *testing.T) (parked <-chan struct{}, release func()) {
	t.Helper()
	var (
		once   sync.Once
		gate   = make(chan struct{})
		opened = make(chan struct{})
	)
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() {
		release()
		transport.SetProtector(nil)
	})
	var parkedOnce sync.Once
	transport.SetProtector(func(fd uintptr) error {
		first := false
		parkedOnce.Do(func() { first = true })
		if first {
			close(opened)
			<-gate
		}
		return nil
	})
	return opened, release
}

// TestCloseDuringFirstDialTakesTheDeviceDown is the S2 regression: Close must own
// the device the first dial is still building.
//
// Pre-fix, start() publishes the device only after it is fully configured, so a
// Close() that runs during the first dial sees nil, reports success and returns
// while the local device — and its peer socket — keeps running.
func TestCloseDuringFirstDialTakesTheDeviceDown(t *testing.T) {
	priv, pub := keyPair(t)
	parked, release := parkPeerSocket(t)

	c, err := New(clientNode(t, 51820, priv, pub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	dialErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err := c.DialContext(ctx, "tcp", "10.9.9.1:80")
		dialErr <- err
	}()
	<-parked // the bring-up now holds a live device and a peer socket

	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()

	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while the first dial was still bringing the device up: "+
			"nothing was cancelled and the local device keeps running", err)
	case <-time.After(300 * time.Millisecond):
	}

	release()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the bring-up was let go")
	}

	// The aborted dial must report the closed client, not a usable tunnel.
	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("the first dial reported success after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first dial did not return after Close")
	}

	// Every later dial observes the closed state without touching the network.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.DialContext(ctx, "tcp", "10.9.9.1:80"); !errors.Is(err, errClosed) {
		t.Fatalf("dial after Close = %v, want %v", err, errClosed)
	}
}

// TestSecondDialHonoursItsOwnDeadline is the S5 regression.
//
// The first dial parks inside the bring-up. The second dial has to queue behind
// it, and that queue must honour the second dial's own context: the engine gives
// every dial its own deadline, so a dial that waits for another one's handshake
// hangs a request until the first one finishes.
func TestSecondDialHonoursItsOwnDeadline(t *testing.T) {
	priv, pub := keyPair(t)
	parked, release := parkPeerSocket(t)
	defer release()

	c, err := New(clientNode(t, 51820, priv, pub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = c.DialContext(ctx, "tcp", "10.9.9.1:80")
	}()
	<-parked

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	res := make(chan error, 1)
	go func() {
		_, err := c.DialContext(ctx, "tcp", "10.9.9.1:80")
		res <- err
	}()
	select {
	case err := <-res:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued dial = %v, want %v", err, context.DeadlineExceeded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued dial ignored its own 300ms deadline and is still waiting for the first bring-up")
	}
}

// TestProtectedSocketBelongsToThePeer keeps the bind honest while the lifecycle
// changes land: the socket that carries the tunnel is the one the protector saw.
func TestProtectedSocketBelongsToThePeer(t *testing.T) {
	priv, pub := keyPair(t)
	var fd int64
	var calls int64
	transport.SetProtector(func(f uintptr) error {
		atomic.AddInt64(&calls, 1)
		atomic.StoreInt64(&fd, int64(f))
		return nil
	})
	t.Cleanup(func() { transport.SetProtector(nil) })

	c, err := New(clientNode(t, 51820, priv, pub))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, _ = c.DialContext(ctx, "tcp", "10.9.9.1:80")

	if atomic.LoadInt64(&calls) == 0 {
		t.Fatal("peer socket was not protected")
	}
	if got := int(atomic.LoadInt64(&fd)); got <= 2 {
		t.Fatalf("protector saw fd %d, want a real descriptor", got)
	}
}
