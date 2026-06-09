package e2e

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/cli"
	"github.com/torkve/bidichan/internal/daemon"
)

const wrapperPSKHex = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"

// startWrapperServer brings up an in-process listen daemon with a stable,
// pinnable cert and returns its transport bind address and the cert path the
// client must pin via --cacert.
func startWrapperServer(t *testing.T) (bindAddr, certPath string) {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	psk := mustPSK(t)
	tmp := t.TempDir()
	srvSock := filepath.Join(tmp, "srv.sock")

	certPEM, keyPEM := mustGenCertPEM(t, "example.test")
	certPath = filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	mustWrite(t, certPath, certPEM, 0o644)
	mustWrite(t, keyPath, keyPEM, 0o644)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bindAddr = probe.Addr().String()
	probe.Close()

	srv, err := daemon.New(daemon.Config{
		Mode:          daemon.ModeListen,
		BindAddr:      bindAddr,
		Hostname:      "example.test",
		PSK:           psk,
		CertPath:      certPath,
		KeyPath:       keyPath,
		ControlSocket: srvSock,
		Logger:        logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go srv.Run(ctx)
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	waitSocket(t, srvSock)
	return bindAddr, certPath
}

// freePort returns a currently-free localhost port number as a string.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// TestConnectCommandForward runs `connect … --channel "forward …" -- bash -c …`
// and proves (a) the wrapper exits 0 and (b) the forward listener was bound
// before the command ran: the command reaches an echo server through it.
func TestConnectCommandForward(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	bindAddr, certPath := startWrapperServer(t)
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	tmp := t.TempDir()
	out := filepath.Join(tmp, "out")
	port := freePort(t)
	cliSock := filepath.Join(tmp, "cli.sock")

	script := fmt.Sprintf(
		"exec 3<>/dev/tcp/127.0.0.1/%s; printf PING >&3; head -c4 <&3 > %s",
		port, out,
	)
	code := cli.Execute([]string{
		"connect",
		"--addr", bindAddr,
		"--hostname", "example.test",
		"--psk", wrapperPSKHex,
		"--cacert", certPath,
		"--socket", cliSock,
		"--channel", "forward -L 127.0.0.1:" + port + ":" + echoAddr,
		"--", bashPath, "-c", script,
	})
	if code != 0 {
		t.Fatalf("wrapper exit code = %d, want 0", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if string(got) != "PING" {
		t.Fatalf("forward round-trip: got %q want %q", got, "PING")
	}
	// The daemon should have torn itself down: the control socket is gone.
	if _, err := os.Stat(cliSock); !os.IsNotExist(err) {
		t.Fatalf("control socket still present after wrapper exit: %v", err)
	}
}

// TestConnectOnPeerDown proves the connect daemon fires OnPeerDown when the
// peer session ends — the hook the wrapper uses to announce tunnel loss.
func TestConnectOnPeerDown(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	psk := mustPSK(t)
	tmp := t.TempDir()
	srvSock := filepath.Join(tmp, "srv.sock")
	cliSock := filepath.Join(tmp, "cli.sock")

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
		Mode: daemon.ModeListen, BindAddr: bindAddr, Hostname: "example.test",
		PSK: psk, CertPath: certPath, KeyPath: keyPath, ControlSocket: srvSock, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, srvCancel := context.WithCancel(context.Background())
	go srv.Run(srvCtx)
	t.Cleanup(func() { srvCancel(); _ = srv.Close() })
	waitSocket(t, srvSock)

	ready := make(chan struct{})
	down := make(chan struct{})
	cli, err := daemon.New(daemon.Config{
		Mode: daemon.ModeConnect, RemoteAddr: bindAddr, Hostname: "example.test",
		PSK: psk, CACert: certPath, ControlSocket: cliSock, Logger: logger,
		OnReady:    func() { close(ready) },
		OnPeerDown: func() { close(down) },
	})
	if err != nil {
		t.Fatal(err)
	}
	cliCtx, cliCancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- cli.Run(cliCtx) }()
	t.Cleanup(func() { cliCancel(); _ = cli.Close() })

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("OnReady never fired")
	}
	// Ensure the server has registered the peer, so srv.Close() actually
	// tears the connection down (otherwise it races and closes nothing).
	waitForPeer(t, srvSock)

	// Drop the server end; the connect side's peer should go down.
	srvCancel()
	_ = srv.Close()
	select {
	case <-down:
	case <-time.After(5 * time.Second):
		t.Fatal("OnPeerDown never fired after peer loss")
	}

	// The connect daemon must not hang after losing its only peer: Run returns
	// a non-nil error so the process exits non-zero (Restart=on-failure redials).
	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("connect daemon Run returned nil on peer loss; want an error so it exits non-zero")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connect daemon did not exit after peer loss")
	}
}

// TestConnectCommandExitCode proves the wrapper propagates the command's exit
// status.
func TestConnectCommandExitCode(t *testing.T) {
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	bindAddr, certPath := startWrapperServer(t)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"exit7", []string{"-c", "exit 7"}, 7},
		{"false", []string{"-c", "exit 1"}, 1},
		{"true", []string{"-c", "exit 0"}, 0},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), fmt.Sprintf("cli-%d.sock", i))
			full := []string{
				"connect",
				"--addr", bindAddr,
				"--hostname", "example.test",
				"--psk", wrapperPSKHex,
				"--cacert", certPath,
				"--socket", sock,
				"--", shPath,
			}
			full = append(full, tc.args...)
			got := cli.Execute(full)
			if got != tc.want {
				t.Fatalf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}
