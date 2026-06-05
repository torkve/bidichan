package e2e

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// TestTwoHopProxyJumpRecipe is the regression guard for the documented
// "Two-hop deployment" recipe in README.md. It composes three real peers
// — A (the client), B (the jump host), C (the final target) — and drives
// a forward channel through both hops. The inner bidichan TLS+PSK
// session is end-to-end between A and C; B sees only ciphertext.
//
// The recipe in the README is the operator-facing equivalent of this
// flow: the only thing different at the binary level is that each peer
// would live in its own `bidichan listen` or `bidichan connect` daemon.
// If this test ever breaks, the README is misleading and needs an edit.
func TestTwoHopProxyJumpRecipe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pskB := twohopPSK(0x01)
	pskC := twohopPSK(0x02)
	logger := log.New(io.Discard, "", 0)

	// Stand up B (the jump host) — a normal bidichan listener.
	bLis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname: "jump.test", PSK: pskB, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bLis.Close()
	bAcceptCh := make(chan *peer.Peer, 1)
	go acceptOne(ctx, t, bLis, logger, bAcceptCh)

	// Stand up C (the final target) — also a normal bidichan listener.
	cLis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname: "cdn.test", PSK: pskC, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cLis.Close()
	cAcceptCh := make(chan *peer.Peer, 1)
	go acceptOne(ctx, t, cLis, logger, cAcceptCh)

	// Echo target that the final-side channel will reach.
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	// Step 1 of the recipe: A's first peer dials B.
	aViaBConn, err := transport.Dial(ctx, bLis.Addr().String(), transport.ClientConfig{
		Hostname: "jump.test", PSK: pskB, RootCAs: rootsFor(t, bLis),
	})
	if err != nil {
		t.Fatalf("A->B dial: %v", err)
	}
	aViaB := newPeerOrDie(t, peer.RoleClient, aViaBConn, logger)
	defer aViaB.Close()
	bPeer := waitPeer(t, bAcceptCh)
	defer bPeer.Close()

	// Step 2 of the recipe: open a forward channel through B whose
	// target is C's bidichan port. This is the operator-equivalent of
	// `bidichan channel open forward -L 2222:cdn:443 --socket A-via-B.sock`.
	openCtx, openCancel := context.WithTimeout(ctx, 5*time.Second)
	defer openCancel()
	if _, err := aViaB.OpenChannel(openCtx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: cLis.Addr().String(),
	}); err != nil {
		t.Fatalf("open jump-forward: %v", err)
	}
	jumpListener := waitForListener(t, aViaB, peer.KindForward)
	if jumpListener == "" {
		t.Fatal("jump-forward listener never bound")
	}
	t.Logf("step 2: jump forward bound at %s -> C@%s", jumpListener, cLis.Addr())

	// Step 3 of the recipe: A's second peer dials C *through* the
	// jump forward. transport.Dial has no idea it's traversing a
	// tunnel — the inner TLS+PSK+TLS-binding all live between A and C.
	aToCConn, err := transport.Dial(ctx, jumpListener, transport.ClientConfig{
		Hostname: "cdn.test", PSK: pskC, RootCAs: rootsFor(t, cLis),
	})
	if err != nil {
		t.Fatalf("A->C-via-B dial: %v", err)
	}
	aToC := newPeerOrDie(t, peer.RoleClient, aToCConn, logger)
	defer aToC.Close()
	cPeer := waitPeer(t, cAcceptCh)
	defer cPeer.Close()
	t.Logf("step 3: inner peer to C established through B")

	// Drive a workload through the inner session: a forward channel
	// from A to an echo on C's side.
	if _, err := aToC.OpenChannel(openCtx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	}); err != nil {
		t.Fatalf("open work channel: %v", err)
	}
	workAddr := waitForListener(t, aToC, peer.KindForward)
	if workAddr == "" {
		t.Fatal("work channel listener never bound")
	}

	// Round-trip a payload all the way through A → B → C → echo and back.
	conn, err := net.Dial("tcp", workAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("two-hop-works")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
}

func twohopPSK(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i) ^ seed
	}
	return b
}

func acceptOne(ctx context.Context, t *testing.T, lis *transport.Listener, logger *log.Logger, out chan<- *peer.Peer) {
	c, err := lis.Accept(ctx)
	if err != nil {
		return
	}
	p, err := peer.NewPeer(peer.RoleServer, c, "srv", logger)
	if err != nil {
		return
	}
	channel.Register(p)
	if err := p.Start(ctx); err != nil {
		return
	}
	out <- p
}

func newPeerOrDie(t *testing.T, role peer.Role, c net.Conn, logger *log.Logger) *peer.Peer {
	t.Helper()
	p, err := peer.NewPeer(role, c, "p", logger)
	if err != nil {
		t.Fatal(err)
	}
	channel.Register(p)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p
}

func waitPeer(t *testing.T, ch <-chan *peer.Peer) *peer.Peer {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for peer accept")
		return nil
	}
}
