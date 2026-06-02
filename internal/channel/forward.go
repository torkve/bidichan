package channel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/torkve/bidichan/internal/peer"
)

// ForwardHandler implements peer.ChannelHandler for raw TCP forwarding
// (both direct and reverse).
//
// Semantics:
//   - Whichever peer the spec marks as ListenSide binds a TCP listener at
//     ListenAddr.
//   - On each inbound conn the listening side opens a new yamux stream with
//     the channel header attached and pipes bytes both ways.
//   - The opposite side dials TargetAddr for each stream and pipes bytes.
type ForwardHandler struct{}

func (h *ForwardHandler) HandleOpen(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage) (json.RawMessage, peer.ChannelRunner, error) {
	var spec peer.ForwardSpec
	if err := json.Unmarshal(specRaw, &spec); err != nil {
		return nil, nil, fmt.Errorf("forward spec: %w", err)
	}
	return setupForward(ctx, p, chID, spec, false)
}

func (h *ForwardHandler) HandleOriginate(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage, _ json.RawMessage) (peer.ChannelRunner, error) {
	var spec peer.ForwardSpec
	if err := json.Unmarshal(specRaw, &spec); err != nil {
		return nil, fmt.Errorf("forward spec: %w", err)
	}
	_, runner, err := setupForward(ctx, p, chID, spec, true)
	return runner, err
}

func (h *ForwardHandler) HandleStream(ctx context.Context, p *peer.Peer, runner peer.ChannelRunner, stream net.Conn, _ json.RawMessage) error {
	fr := runner.(*forwardRunner)
	// If we're the listener side, this stream shouldn't happen — listeners
	// originate streams, they don't receive them. We only handle inbound
	// streams as the dialer side.
	if fr.role == roleListener {
		_ = stream.Close()
		return errors.New("forward: listener received unexpected stream")
	}
	defer stream.Close()
	target := fr.spec.TargetAddr
	dialed, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer dialed.Close()
	pipeBoth(stream, dialed)
	return nil
}

// forwardRunner owns the lifecycle of a forwarding channel on this side.
type forwardRunner struct {
	spec peer.ForwardSpec
	role forwardRole

	lis       net.Listener
	closeOnce sync.Once
	closed    chan struct{}
}

type forwardRole int

const (
	roleListener forwardRole = iota
	roleDialer
)

func (r *forwardRunner) Close() error {
	r.closeOnce.Do(func() {
		if r.lis != nil {
			_ = r.lis.Close()
		}
		close(r.closed)
	})
	return nil
}

func (r *forwardRunner) Description() string {
	switch r.role {
	case roleListener:
		return fmt.Sprintf("forward listen=%s -> peer:%s", r.lis.Addr(), r.spec.TargetAddr)
	default:
		return fmt.Sprintf("forward dial=%s (listener on peer at %s)", r.spec.TargetAddr, r.spec.ListenAddr)
	}
}

// setupForward decides which role this side plays, sets up the listener if
// needed, and returns the runner plus any ack info to send back.
//
// originator is true when *we* sent the OpenChannel; false when we received it.
func setupForward(ctx context.Context, p *peer.Peer, chID uint64, spec peer.ForwardSpec, originator bool) (json.RawMessage, peer.ChannelRunner, error) {
	weListen := whoListens(spec.ListenSide, originator)

	r := &forwardRunner{
		spec:   spec,
		closed: make(chan struct{}),
	}
	if !weListen {
		r.role = roleDialer
		return nil, r, nil
	}
	r.role = roleListener

	lis, err := net.Listen("tcp", spec.ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", spec.ListenAddr, err)
	}
	r.lis = lis
	go r.acceptLoop(ctx, p, chID)

	info, _ := json.Marshal(peer.AckInfoListener{BoundAddr: lis.Addr().String()})
	return info, r, nil
}

func (r *forwardRunner) acceptLoop(ctx context.Context, p *peer.Peer, chID uint64) {
	for {
		c, err := r.lis.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			s, err := p.OpenStream(chID, peer.ForwardStreamMeta{Target: r.spec.TargetAddr})
			if err != nil {
				return
			}
			defer s.Close()
			pipeBoth(c, s)
		}()
	}
}

// whoListens returns true if we are the side that hosts the listener for this
// channel.
//   - SideOriginator means: the peer that called OpenChannel hosts the listener.
//     So we host the listener iff we are the originator.
//   - SideResponder means: the peer that received the OpenChannel hosts the
//     listener — we host it iff we are NOT the originator.
func whoListens(s peer.Side, originator bool) bool {
	switch s {
	case peer.SideOriginator:
		return originator
	case peer.SideResponder:
		return !originator
	default:
		return false
	}
}

// pipeBoth copies bytes in both directions between a and b until either side
// closes or errors out. Returns after both copy goroutines have completed.
func pipeBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		halfClose(a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		halfClose(b)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// halfClose tries to issue a half-close on the writable side so EOF
// propagates to the peer. If the conn type doesn't expose CloseWrite, we
// fall back to a full Close which is fine for our forwarding loops.
func halfClose(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
