package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/cli"
	"github.com/torkve/bidichan/internal/daemon"
)

// syncBuffer is a goroutine-safe log sink the tests poll for daemon output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForLog(t *testing.T, b *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), substr) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log never contained %q; log:\n%s", substr, b.String())
}

// startRetryPair starts a listen daemon and a connect daemon whose single
// auto-channel forward wants blockedAddr, which the caller holds. Returns the
// connect side's control socket, log sink, and a stop func shutting the
// connect daemon down (also registered as cleanup).
func startRetryPair(t *testing.T, blockedAddr, echoAddr string) (cliSock string, dialerLog *syncBuffer, stop func()) {
	t.Helper()
	psk := mustPSK(t)
	tmp := t.TempDir()
	srvSock := filepath.Join(tmp, "srv.sock")
	cliSock = filepath.Join(tmp, "cli.sock")

	certPEM, keyPEM := mustGenCertPEM(t, "example.test")
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	mustWrite(t, certPath, certPEM, 0o644)
	mustWrite(t, keyPath, keyPEM, 0o644)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bindAddr := probe.Addr().String()
	probe.Close()

	srv, err := daemon.New(daemon.Config{
		Mode:          daemon.ModeListen,
		BindAddr:      bindAddr,
		Hostname:      "example.test",
		PSK:           psk,
		CertPath:      certPath,
		KeyPath:       keyPath,
		ControlSocket: srvSock,
		Logger:        log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctxSrv, cancelSrv := context.WithCancel(context.Background())
	go srv.Run(ctxSrv)
	t.Cleanup(func() { cancelSrv(); _ = srv.Close() })
	waitSocket(t, srvSock)

	dialerLog = &syncBuffer{}
	dialer, err := daemon.New(daemon.Config{
		Mode:          daemon.ModeConnect,
		RemoteAddr:    bindAddr,
		Hostname:      "example.test",
		PSK:           psk,
		CACert:        certPath,
		ControlSocket: cliSock,
		Logger:        log.New(dialerLog, "", 0),
		AutoChannels: []daemon.AutoChannel{
			{Kind: "forward", Side: "local", ListenAddr: blockedAddr, TargetAddr: echoAddr},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctxCli, cancelCli := context.WithCancel(context.Background())
	go dialer.Run(ctxCli)
	stop = func() { cancelCli(); _ = dialer.Close() }
	t.Cleanup(stop)
	waitSocket(t, cliSock)
	waitForPeer(t, srvSock)
	waitForPeer(t, cliSock)
	return cliSock, dialerLog, stop
}

// TestAutoChannelRetryAfterBindConflict reproduces the restart race: the
// auto-channel's listen port is still held when the daemon comes up, the
// first open fails with EADDRINUSE, and the channel must appear once the
// port frees instead of staying lost.
func TestAutoChannelRetryAfterBindConflict(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blockedAddr := blocker.Addr().String()

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	cliSock, dialerLog, _ := startRetryPair(t, blockedAddr, echoAddr)

	waitForLog(t, dialerLog, "auto-channel forward failed")
	blocker.Close()

	cc, err := cli.DialCtrl(cliSock)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	var listenAddr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		statusData, err := cc.Call(daemon.ActionStatus, nil)
		if err != nil {
			t.Fatal(err)
		}
		var status daemon.StatusResponse
		_ = json.Unmarshal(statusData, &status)
		for _, p := range status.Peers {
			for _, ch := range p.Channels {
				if a := extractListenAddr(ch.Description); a != "" {
					listenAddr = a
				}
			}
		}
		if listenAddr != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if listenAddr == "" {
		t.Fatalf("auto-channel never recovered after port freed; log:\n%s", dialerLog.String())
	}

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("retry-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}

// TestAutoChannelRetryPendingShutdown holds the port for the whole test:
// shutting the daemon down while the retry loop is still waiting must make
// the retry goroutine exit.
func TestAutoChannelRetryPendingShutdown(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	_, dialerLog, stop := startRetryPair(t, blocker.Addr().String(), echoAddr)
	waitForLog(t, dialerLog, "auto-channel forward failed")
	stop()

	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for {
		stacks := buf[:runtime.Stack(buf, true)]
		if !bytes.Contains(stacks, []byte("retryAutoChannel")) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("retryAutoChannel goroutine still running after shutdown:\n%s", stacks)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
