package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// tcpRelay sits between the client and the listener and can drop every
// connection running through it, which is what a network outage looks like
// from the client's side: the socket dies, and a redial arrives at the server
// as a brand new connection.
type tcpRelay struct {
	lis    net.Listener
	target string

	mu    sync.Mutex
	conns []net.Conn
}

func newTCPRelay(t *testing.T, target string) *tcpRelay {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r := &tcpRelay{lis: lis, target: target}
	go r.accept()
	t.Cleanup(r.close)
	return r
}

func (r *tcpRelay) addr() string { return r.lis.Addr().String() }

func (r *tcpRelay) accept() {
	for {
		in, err := r.lis.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp", r.target)
		if err != nil {
			_ = in.Close()
			continue
		}
		r.mu.Lock()
		r.conns = append(r.conns, in, out)
		r.mu.Unlock()
		go func() { _, _ = io.Copy(out, in); _ = out.Close() }()
		go func() { _, _ = io.Copy(in, out); _ = in.Close() }()
	}
}

// cut drops every connection currently crossing the relay.
func (r *tcpRelay) cut() {
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (r *tcpRelay) close() {
	_ = r.lis.Close()
	r.cut()
}

// resumablePair is pair() with two differences: the client reaches the
// listener through a relay the test can cut, and it dials with DialSession so
// the connection resumes instead of dying.
func resumablePair(t *testing.T, hostname string) (*peer.Peer, *tcpRelay, func()) {
	t.Helper()
	psk := mustPSK(t)
	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(io.Discard, "", 0)

	lis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname:     hostname,
		PSK:          psk,
		Logger:       logger,
		ResumeConfig: transport.ResumeConfig{Grace: 10 * time.Second},
	})
	if err != nil {
		cancel()
		t.Fatalf("Listen: %v", err)
	}

	// Keep accepting for the whole test: a reconnecting client arrives as a
	// new connection, and only the accept loop drives the handshake that
	// reattaches it to its existing session.
	var (
		srvMu    sync.Mutex
		srvPeers []*peer.Peer
	)
	go func() {
		for {
			c, err := lis.Accept(ctx)
			if err != nil {
				return
			}
			p, err := peer.NewPeer(peer.RoleServer, c, "srv", logger)
			if err != nil {
				_ = c.Close()
				continue
			}
			channel.Register(p)
			channel.RegisterShell(p, true)
			if err := p.Start(ctx); err != nil {
				_ = p.Close()
				continue
			}
			srvMu.Lock()
			srvPeers = append(srvPeers, p)
			srvMu.Unlock()
		}
	}()

	relay := newTCPRelay(t, lis.Addr().String())

	cliConn, err := transport.DialSession(ctx, relay.addr(), transport.ClientConfig{
		Hostname:     hostname,
		PSK:          psk,
		RootCAs:      rootsFor(t, lis),
		ResumeConfig: transport.ResumeConfig{Grace: 10 * time.Second, Logger: logger},
	})
	if err != nil {
		cancel()
		_ = lis.Close()
		t.Fatalf("DialSession: %v", err)
	}
	if _, ok := cliConn.(*transport.Session); !ok {
		cancel()
		_ = lis.Close()
		t.Fatal("DialSession did not negotiate a resumable session")
	}

	cliPeer, err := peer.NewPeer(peer.RoleClient, cliConn, "cli", logger)
	if err != nil {
		cancel()
		_ = lis.Close()
		t.Fatalf("NewPeer: %v", err)
	}
	channel.Register(cliPeer)
	channel.RegisterShell(cliPeer, true)
	if err := cliPeer.Start(ctx); err != nil {
		cancel()
		_ = lis.Close()
		t.Fatalf("Start client: %v", err)
	}

	teardown := func() {
		_ = cliPeer.Close()
		srvMu.Lock()
		for _, p := range srvPeers {
			_ = p.Close()
		}
		srvMu.Unlock()
		cancel()
		_ = lis.Close()
	}
	return cliPeer, relay, teardown
}

// TestResumeKeepsInnerConnectionAlive is the whole point of the resume layer:
// a TCP connection carried inside a forward channel must survive the tunnel's
// network dying and coming back, without the application on either end seeing
// so much as an error.
func TestResumeKeepsInnerConnectionAlive(t *testing.T) {
	cli, relay, teardown := resumablePair(t, "example.test")
	defer teardown()

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	chID, err := cli.OpenChannel(ctx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	})
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}

	listenAddr := waitForListenAddr(t, cli)
	inner, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer inner.Close()
	br := bufio.NewReader(inner)

	roundTrip := func(msg string) string {
		t.Helper()
		_ = inner.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := fmt.Fprintln(inner, msg); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read after %q: %v", msg, err)
		}
		return line[:len(line)-1]
	}

	if got := roundTrip("before"); got != "before" {
		t.Fatalf("before the cut: got %q", got)
	}

	// Pull the network out from under the tunnel.
	relay.cut()

	// The very same TCP connection must keep working once the transport has
	// reconnected underneath it — no reconnect logic in the application, no
	// error surfaced, no bytes lost.
	if got := roundTrip("after"); got != "after" {
		t.Fatalf("after the cut: got %q", got)
	}

	// And the channel is the one we opened, not a replacement.
	found := false
	for _, c := range cli.Snapshot() {
		if c.ID == chID {
			found = true
		}
	}
	if !found {
		t.Fatalf("channel %d did not survive the outage", chID)
	}
}

// A second cut, while the first reconnect is still fresh, must be just as
// survivable — the failure mode to catch is state that is only correct the
// first time round.
func TestResumeSurvivesRepeatedOutages(t *testing.T) {
	cli, relay, teardown := resumablePair(t, "example.test")
	defer teardown()

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cli.OpenChannel(ctx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	}); err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}

	inner, err := net.Dial("tcp", waitForListenAddr(t, cli))
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer inner.Close()
	br := bufio.NewReader(inner)

	for i := 0; i < 3; i++ {
		relay.cut()
		msg := fmt.Sprintf("round-%d", i)
		_ = inner.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := fmt.Fprintln(inner, msg); err != nil {
			t.Fatalf("write round %d: %v", i, err)
		}
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read round %d: %v", i, err)
		}
		if got := line[:len(line)-1]; got != msg {
			t.Fatalf("round %d: got %q want %q", i, got, msg)
		}
	}
}

// A server that does not offer resumption — an older build, or one started
// with --no-resume — must still work. The client falls back to a plain
// connection and everything behaves as it did before the feature existed.
func TestDialSessionFallsBackWhenServerRefusesResume(t *testing.T) {
	psk := mustPSK(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := log.New(io.Discard, "", 0)

	lis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname:      "example.test",
		PSK:           psk,
		Logger:        logger,
		DisableResume: true,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	serverCh := make(chan *peer.Peer, 1)
	go func() {
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
		serverCh <- p
	}()

	conn, err := transport.DialSession(ctx, lis.Addr().String(), transport.ClientConfig{
		Hostname:     "example.test",
		PSK:          psk,
		RootCAs:      rootsFor(t, lis),
		ResumeConfig: transport.ResumeConfig{Logger: logger},
	})
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	if _, isSession := conn.(*transport.Session); isSession {
		t.Fatal("client wrapped a session even though the server refused resumption")
	}

	cli, err := peer.NewPeer(peer.RoleClient, conn, "cli", logger)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	channel.Register(cli)
	if err := cli.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cli.Close()

	select {
	case p := <-serverCh:
		defer p.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("server peer never came up")
	}

	// And the tunnel is fully usable, not merely established.
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()
	openCtx, openCancel := context.WithTimeout(ctx, 5*time.Second)
	defer openCancel()
	if _, err := cli.OpenChannel(openCtx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	}); err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	inner, err := net.Dial("tcp", waitForListenAddr(t, cli))
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer inner.Close()
	_ = inner.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(inner, "legacy"); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(inner).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := line[:len(line)-1]; got != "legacy" {
		t.Fatalf("got %q want %q", got, "legacy")
	}
}

// waitForListenAddr reads the bound address of the peer's forward channel out
// of its snapshot, which is where the kernel-assigned port shows up.
func waitForListenAddr(t *testing.T, p *peer.Peer) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range p.Snapshot() {
			if c.Kind == peer.KindForward && c.Description != "" {
				if addr := extractListenAddr(c.Description); addr != "" {
					return addr
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("could not learn the forward listener address")
	return ""
}
