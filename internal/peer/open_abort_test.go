package peer

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

const kindGate ChannelKind = "gate-test"

type gateRunner struct {
	id     uint64
	closed chan<- uint64
	once   sync.Once
}

func (r *gateRunner) Close() error {
	r.once.Do(func() {
		if r.closed != nil {
			r.closed <- r.id
		}
	})
	return nil
}

func (r *gateRunner) Description() string { return "gate-test" }

// gateHandler blocks HandleOpen until the test releases it, modelling a slow
// responder-side setup (e.g. a listener bind) that an originator timeout can
// outrun.
type gateHandler struct {
	gate   chan struct{}
	closed chan uint64
}

func (h *gateHandler) HandleOpen(_ context.Context, _ *Peer, chID uint64, _ json.RawMessage) (json.RawMessage, ChannelRunner, error) {
	<-h.gate
	return nil, &gateRunner{id: chID, closed: h.closed}, nil
}

func (h *gateHandler) HandleOriginate(_ context.Context, _ *Peer, chID uint64, _, _ json.RawMessage) (ChannelRunner, error) {
	return &gateRunner{id: chID}, nil
}

func (h *gateHandler) HandleStream(_ context.Context, _ *Peer, _ ChannelRunner, s net.Conn, _ json.RawMessage) error {
	return s.Close()
}

func startPeerPair(t *testing.T) (client, server *Peer, h *gateHandler) {
	t.Helper()
	logger := log.New(io.Discard, "", 0)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	cconn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sconn, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}

	client, err = NewPeer(RoleClient, cconn, "client", logger)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewPeer(RoleServer, sconn, "server", logger)
	if err != nil {
		t.Fatal(err)
	}
	h = &gateHandler{gate: make(chan struct{}, 1), closed: make(chan uint64, 16)}
	client.RegisterHandler(kindGate, h)
	server.RegisterHandler(kindGate, h)

	ctx, cancel := context.WithCancel(context.Background())
	srvErr := make(chan error, 1)
	go func() { srvErr <- server.Start(ctx) }()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		cancel()
	})
	return client, server, h
}

// TestOpenChannelTimeoutAbortsInflightOpen pins the close-outruns-open
// protocol: when the originator's OpenChannel deadline expires while the
// responder is still inside HandleOpen, the close it sends must tear the
// responder's channel down once the open completes — never strand the runner.
// The release moment is randomized around the deadline so both orderings
// (close processed before and after the channel is stored) occur across
// iterations; run under -race.
func TestOpenChannelTimeoutAbortsInflightOpen(t *testing.T) {
	client, server, h := startPeerPair(t)

	for i := 0; i < 200; i++ {
		delay := time.Duration(rand.IntN(10)) * time.Millisecond
		go func() {
			time.Sleep(delay)
			h.gate <- struct{}{}
		}()

		octx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		id, err := client.OpenChannel(octx, kindGate, struct{}{})
		cancel()
		if err == nil {
			// The open won the race: a legitimate channel — close it so the
			// responder tears down, then fall through to the common checks.
			_ = client.CloseChannelByID(id, "test done")
		}

		// Exactly one responder-side runner must be closed per iteration,
		// whichever way the race went.
		select {
		case cid := <-h.closed:
			if _, ok := server.ChannelRunner(cid); ok {
				t.Fatalf("iteration %d: responder still tracks channel %d after teardown", i, cid)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: responder runner never closed (channel stranded, open err=%v)", i, err)
		}
	}
}
