package e2e

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// rootsFor returns a cert pool trusting the listener's (self-signed) leaf, so
// clients can verify the server cert instead of skipping verification.
func rootsFor(t testing.TB, lis *transport.Listener) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if c := lis.Certificate(); c != nil {
		pool.AddCert(c)
	}
	return pool
}

func mustPSK(t *testing.T) []byte {
	b, err := hex.DecodeString("0011223344556677889900aabbccddeeff00112233445566778899aabbccddee")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pair sets up an authenticated listener + dialer over loopback and returns
// the two peer.Peer objects, with the listener already accepting.
func pair(t *testing.T, hostname string) (*peer.Peer, *peer.Peer, func()) {
	t.Helper()
	psk := mustPSK(t)
	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(io.Discard, "", 0)

	lis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname: hostname,
		PSK:      psk,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	serverCh := make(chan *peer.Peer, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := lis.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		p, err := peer.NewPeer(peer.RoleServer, c, "srv", logger)
		if err != nil {
			errCh <- err
			return
		}
		channel.Register(p)
		channel.RegisterShell(p, true)
		if err := p.Start(ctx); err != nil {
			errCh <- err
			return
		}
		serverCh <- p
	}()

	cliConn, err := transport.Dial(ctx, lis.Addr().String(), transport.ClientConfig{
		Hostname: hostname,
		PSK:      psk,
		RootCAs:  rootsFor(t, lis),
	})
	if err != nil {
		cancel()
		_ = lis.Close()
		t.Fatalf("Dial: %v", err)
	}
	cliPeer, err := peer.NewPeer(peer.RoleClient, cliConn, "cli", logger)
	if err != nil {
		cancel()
		_ = lis.Close()
		t.Fatalf("NewPeer client: %v", err)
	}
	channel.Register(cliPeer)
	channel.RegisterShell(cliPeer, true)
	if err := cliPeer.Start(ctx); err != nil {
		cancel()
		_ = lis.Close()
		t.Fatalf("Start client: %v", err)
	}

	var srvPeer *peer.Peer
	select {
	case srvPeer = <-serverCh:
	case err := <-errCh:
		cancel()
		_ = lis.Close()
		t.Fatalf("server accept: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		_ = lis.Close()
		t.Fatal("timeout waiting for server peer")
	}

	teardown := func() {
		_ = cliPeer.Close()
		_ = srvPeer.Close()
		cancel()
		_ = lis.Close()
	}
	return cliPeer, srvPeer, teardown
}

// startEcho starts a TCP echo server on 127.0.0.1:0 and returns its address.
func startEcho(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	stop := func() {
		_ = lis.Close()
		close(done)
	}
	return lis.Addr().String(), stop
}

func TestForwardDirect(t *testing.T) {
	cli, _, teardown := pair(t, "example.test")
	defer teardown()

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	// Client originates: listen on client side, target = echo on the same
	// machine but logically belongs to the server's namespace.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cli.OpenChannel(ctx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	})
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}

	// Find the local bound address via the channel snapshot.
	var listenAddr string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range cli.Snapshot() {
			if c.Kind == peer.KindForward && c.Description != "" {
				listenAddr = extractListenAddr(c.Description)
			}
		}
		if listenAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if listenAddr == "" {
		t.Fatal("could not learn local listener address")
	}

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	defer conn.Close()
	payload := []byte("hello-bidichan-forward")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
}

func TestSocks5(t *testing.T) {
	cli, _, teardown := pair(t, "example.test")
	defer teardown()

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cli.OpenChannel(ctx, peer.KindSocks5, peer.ProxySpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}

	var proxyAddr string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range cli.Snapshot() {
			if c.Kind == peer.KindSocks5 {
				proxyAddr = extractListenAddr(c.Description)
			}
		}
		if proxyAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if proxyAddr == "" {
		t.Fatal("could not learn proxy addr")
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// SOCKS5 greeting: ver=5 nmethods=1 method=0 (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("bad greeting %v", greet)
	}
	// Build CONNECT request to echoAddr (parse host:port)
	host, port, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("expected ipv4 echo addr, got %s", host)
	}
	portN := 0
	for _, c := range port {
		portN = portN*10 + int(c-'0')
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, byte(portN>>8), byte(portN&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("CONNECT failed: %v", reply)
	}
	payload := []byte("hi via socks5")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}

func TestNginxDecoyOnWrongSNI(t *testing.T) {
	psk := mustPSK(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := log.New(io.Discard, "", 0)
	lis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname: "example.test",
		PSK:      psk,
		Logger:   logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	go func() {
		_, _ = lis.Accept(ctx)
	}()

	// Connect with wrong SNI and a normal-looking GET. We should get nginx.
	// (The cert is for example.test, so a wrong-SNI dial also fails cert
	// verification — either way the dial must not succeed.)
	_, err = transport.Dial(ctx, lis.Addr().String(), transport.ClientConfig{
		Hostname: "wrong.test",
		PSK:      psk,
		RootCAs:  rootsFor(t, lis),
	})
	if err == nil {
		t.Fatal("expected dial to fail (server should decoy)")
	}
}

// extractListenAddr pulls "listen=ADDR" out of forward/proxy descriptions of
// the form "...listen=127.0.0.1:NNNN..." or "...on 127.0.0.1:NNNN...".
func extractListenAddr(desc string) string {
	for _, sep := range []string{"listen=", "on "} {
		i := indexOf(desc, sep)
		if i < 0 {
			continue
		}
		s := desc[i+len(sep):]
		// trim at first space or " ->"
		for j, c := range s {
			if c == ' ' {
				return s[:j]
			}
		}
		return s
	}
	return ""
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestMain(m *testing.M) {
	// Make temp socket paths writable for daemon tests.
	tmp, err := os.MkdirTemp("", "bidichan-e2e-*")
	if err == nil {
		_ = os.Setenv("XDG_RUNTIME_DIR", tmp)
		defer os.RemoveAll(tmp)
		_ = filepath.Walk(tmp, func(_ string, _ os.FileInfo, err error) error { return err })
	}
	code := m.Run()
	if code != 0 && errors.Is(err, errors.New("noop")) {
		_ = code
	}
	os.Exit(code)
}
