package e2e

import (
	"context"
	"crypto/x509"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/daemon"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// A listening daemon is idle between connections, so its in-flight-adoption
// counter is normally zero — and an Add that lifts it off zero has to be
// ordered against the wait in Close, or shutdown races the adoption that is
// just starting. The window is one scheduling accident wide, so rather than
// hope for it, keep peers arriving continuously and close in the middle.
//
// There are deliberately no assertions: what this regresses is a data race, so
// it only detects anything under -race. Keep it in a -race lane — without one
// it proves nothing beyond Close not hanging.
func TestListenDaemonCloseRacesIncomingPeer(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	psk := mustPSK(t)
	tmp := t.TempDir()

	certPEM, keyPEM := mustGenCertPEM(t, "example.test")
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	mustWrite(t, certPath, certPEM, 0o644)
	mustWrite(t, keyPath, keyPEM, 0o644)

	roots := x509.NewCertPool()
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("no certs in generated PEM")
	}

	for round := 0; round < 25; round++ {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		bindAddr := probe.Addr().String()
		_ = probe.Close()

		srv, err := daemon.New(daemon.Config{
			Mode: daemon.ModeListen, BindAddr: bindAddr, Hostname: "example.test",
			PSK: psk, CertPath: certPath, KeyPath: keyPath,
			ControlSocket: filepath.Join(tmp, "srv.sock"), Logger: logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan struct{})
		go func() { _ = srv.Run(ctx); close(runDone) }()
		waitListening(t, bindAddr)

		// Keep peers arriving continuously, so one adoption is always in
		// flight when the next begins — that is the state Close has to wait
		// through, and the moment its wait finishes is when a starting
		// adoption can collide with it.
		stop := make(chan struct{})
		var dialers sync.WaitGroup
		for i := 0; i < 6; i++ {
			dialers.Add(1)
			go func() {
				defer dialers.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
					c, err := transport.Dial(dctx, bindAddr, transport.ClientConfig{
						Hostname: "example.test", PSK: psk, RootCAs: roots,
					})
					dcancel()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
		}

		time.Sleep(15 * time.Millisecond)
		_ = srv.Close()

		close(stop)
		dialers.Wait()
		cancel()
		<-runDone
	}
}

// waitListening blocks until something accepts on addr.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

// Shutting the door on adoptions that have not started is only half the
// invariant. One that is already in flight finishes its handshake after Close
// has drained the peer map, and if it registers itself then, nothing will ever
// tear it down: neither of peer.Peer's loops watches the context, so the peer,
// its session and its goroutines outlive the daemon that owned them.
func TestNoPeerSurvivesClose(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	psk := mustPSK(t)
	tmp := t.TempDir()
	certPEM, keyPEM := mustGenCertPEM(t, "example.test")
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	mustWrite(t, certPath, certPEM, 0o644)
	mustWrite(t, keyPath, keyPEM, 0o644)
	roots := x509.NewCertPool()
	pem, _ := os.ReadFile(certPath)
	roots.AppendCertsFromPEM(pem)

	stranded := 0
	for round := 0; round < 10; round++ {
		probe, _ := net.Listen("tcp", "127.0.0.1:0")
		bindAddr := probe.Addr().String()
		probe.Close()
		srv, err := daemon.New(daemon.Config{
			Mode: daemon.ModeListen, BindAddr: bindAddr, Hostname: "example.test",
			PSK: psk, CertPath: certPath, KeyPath: keyPath,
			ControlSocket: filepath.Join(tmp, "s.sock"), Logger: logger,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go srv.Run(ctx)
		waitListening(t, bindAddr)

		// Client that authenticates but delays its yamux control stream, so
		// the server sits inside adoptPeer's p.Start when Close runs.
		done := make(chan struct{})
		go func() {
			defer close(done)
			dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer dcancel()
			c, err := transport.Dial(dctx, bindAddr, transport.ClientConfig{
				Hostname: "example.test", PSK: psk, RootCAs: roots,
			})
			if err != nil {
				return
			}
			// Complete the transport handshake, pause so the server is
			// parked inside adoptPeer's p.Start, then finish the yamux
			// handshake so that Start succeeds *after* Close has run.
			time.Sleep(120 * time.Millisecond)
			cp, err := peer.NewPeer(peer.RoleClient, c, "cli", logger)
			if err != nil {
				return
			}
			defer cp.Close()
			_ = cp.Start(context.Background())
			time.Sleep(200 * time.Millisecond)
		}()
		time.Sleep(60 * time.Millisecond)
		_ = srv.Close()
		time.Sleep(150 * time.Millisecond)
		if n := len(srv.Peers()); n > 0 {
			stranded++
		}
		<-done
		cancel()
	}
	if stranded > 0 {
		t.Fatalf("%d/10 rounds left a peer registered after Close", stranded)
	}
}
