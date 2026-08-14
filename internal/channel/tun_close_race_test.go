package channel

import (
	"io"
	"net"
	"sync"
	"testing"

	"github.com/torkve/bidichan/internal/peer"
)

// stubTUN stands in for the device. Reads block until it is closed, which is
// what a quiet packet interface does, so the pumps behave as they would on a
// real one rather than spinning on an immediate error.
type stubTUN struct {
	closeOnce sync.Once
	done      chan struct{}
}

func newStubTUN() *stubTUN { return &stubTUN{done: make(chan struct{})} }

func (s *stubTUN) Read(p []byte) (int, error) {
	<-s.done
	return 0, io.EOF
}

func (s *stubTUN) Write(p []byte) (int, error) { return len(p), nil }
func (s *stubTUN) Name() string                { return "stub0" }

func (s *stubTUN) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	return nil
}

// Closing a runner while a stream is being attached must be safe.
//
// The two happen on unrelated goroutines: a peer closes channels from its
// control and stream loops, while the attach runs on whichever goroutine opened
// the channel. Reading r.stream without the lock that publishes it is a torn
// read of a two-word interface — the new type word with the old nil data word —
// and calling Close on that dispatches onto a nil receiver, faulting inside the
// runtime. The process then dies of a re-raised signal on whatever thread was
// running, which on a phone is an anonymous native crash.
//
// Run with -race, which is where this shows up as a diagnosis rather than as a
// once-in-a-thousand-runs mystery.
func TestCloseRacesAttachStream(t *testing.T) {
	for i := 0; i < 200; i++ {
		a, b := net.Pipe()
		dev := newStubTUN()
		r := &tunRunner{
			spec:   peer.TUNSpec{MTU: 1400},
			ifce:   dev,
			closed: make(chan struct{}),
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = r.attachStream(a)
		}()
		go func() {
			defer wg.Done()
			_ = r.Close()
		}()
		wg.Wait()
		_ = r.Close()
		_ = a.Close()
		_ = b.Close()
	}
}

// And a runner that is already closed refuses the stream rather than starting
// pumps over something nothing will close.
func TestAttachAfterCloseIsRefused(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	r := &tunRunner{spec: peer.TUNSpec{MTU: 1400}, ifce: newStubTUN(), closed: make(chan struct{})}
	_ = r.Close()

	if err := r.attachStream(a); err == nil {
		t.Fatal("a closed runner accepted a stream")
	}
	// Refusing means taking responsibility for what was handed over.
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Fatal("the refused stream was left open")
	}
}
