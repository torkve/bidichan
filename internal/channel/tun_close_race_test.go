package channel

import (
	"net"
	"sync"
	"testing"

	"github.com/torkve/bidichan/internal/peer"
)

// Closing a runner while a stream is being attached must be safe: a peer closes
// channels from its control and stream loops, while the attach runs on whoever
// opened the channel.
//
// Meaningful only under -race, which is how the suite runs.
func TestCloseRacesAttachStream(t *testing.T) {
	for i := 0; i < 200; i++ {
		a, b := net.Pipe()
		r := &tunRunner{
			spec:   peer.TUNSpec{MTU: 1400},
			ifce:   newFakeTUN(),
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

// A runner that is already closed refuses the stream, rather than starting
// pumps over one nothing will ever close.
func TestAttachAfterCloseIsRefused(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	r := &tunRunner{spec: peer.TUNSpec{MTU: 1400}, ifce: newFakeTUN(), closed: make(chan struct{})}
	_ = r.Close()

	if err := r.attachStream(a); err == nil {
		t.Fatal("a closed runner accepted a stream")
	}
	// Refusing means taking responsibility for what was handed over.
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Fatal("the refused stream was left open")
	}
}
