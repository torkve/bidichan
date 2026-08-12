package e2e

import (
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

// The two ends need not agree on their stream windows.
//
// This is what makes --stream-window usable at all: a small box lowers its own
// and the phone at the other end keeps its large one, with no negotiation and
// no protocol change. The window bounds only the receive window each side
// advertises for itself, so a mismatch has to be survivable — and the way to
// show that is to move more bytes than the smaller window through a forward in
// both directions, not merely to build two peers and see no error.
func TestMismatchedStreamWindowsStillCarryTraffic(t *testing.T) {
	psk := mustPSK(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := log.New(io.Discard, "", 0)

	lis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname: "example.test",
		PSK:      psk,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	// The server holds the smallest window the protocol allows; the client
	// keeps the default. That is the controller-and-phone case exactly.
	serverCh := make(chan *peer.Peer, 1)
	go func() {
		c, err := lis.Accept(ctx)
		if err != nil {
			return
		}
		p, err := peer.NewPeer(peer.RoleServer, c, "srv", logger,
			peer.WithMaxStreamWindow(peer.MinStreamWindow))
		if err != nil {
			return
		}
		channel.Register(p)
		if err := p.Start(ctx); err != nil {
			return
		}
		serverCh <- p
	}()

	cliConn, err := transport.Dial(ctx, lis.Addr().String(), transport.ClientConfig{
		Hostname: "example.test",
		PSK:      psk,
		RootCAs:  rootsFor(t, lis),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cliPeer, err := peer.NewPeer(peer.RoleClient, cliConn, "cli", logger,
		peer.WithMaxStreamWindow(peer.DefaultStreamWindow))
	if err != nil {
		t.Fatalf("NewPeer client: %v", err)
	}
	channel.Register(cliPeer)
	if err := cliPeer.Start(ctx); err != nil {
		t.Fatalf("Start client: %v", err)
	}
	defer cliPeer.Close()

	select {
	case p := <-serverCh:
		defer p.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("the server peer never came up")
	}

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	if _, err := cliPeer.OpenChannel(ctx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	}); err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}

	var listenAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && listenAddr == "" {
		for _, c := range cliPeer.Snapshot() {
			if c.Kind == peer.KindForward && c.Description != "" {
				listenAddr = extractListenAddr(c.Description)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if listenAddr == "" {
		t.Fatal("the forward never bound")
	}

	// Comfortably more than the smaller window, so credit has to be returned
	// repeatedly rather than the whole payload fitting in one grant.
	payload := make([]byte, 4*int(peer.MinStreamWindow))
	for i := range payload {
		payload[i] = byte(i)
	}

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("dial the forward: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	go func() {
		_, _ = conn.Write(payload)
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back through the forward: %v", err)
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("byte %d came back as %d, not %d", i, got[i], payload[i])
		}
	}
}
