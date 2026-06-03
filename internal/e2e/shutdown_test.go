package e2e

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/daemon"
)

// TestListenerDaemonStopsOnContextCancel reproduces the SIGINT hang: a
// listener daemon with no peers should exit promptly when its context is
// cancelled (i.e. when the signal handler calls d.Close()). The previous
// behaviour was that runListen blocked forever inside net.Listener.Accept
// because the transport listener didn't watch the context.
func TestListenerDaemonStopsOnContextCancel(t *testing.T) {
	psk := mustPSK(t)
	tmp := t.TempDir()
	ctrlSock := filepath.Join(tmp, "ctrl.sock")

	// Pick a free TCP port up-front so the test doesn't race on port pickup.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bind := probe.Addr().String()
	probe.Close()

	d, err := daemon.New(daemon.Config{
		Mode:          daemon.ModeListen,
		BindAddr:      bind,
		Hostname:      "example.test",
		PSK:           psk,
		ControlSocket: ctrlSock,
		Logger:        log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { runDone <- d.Run(ctx) }()

	// Wait for the ctrl socket to appear so we know Run has set up its
	// state. If we Close before Run set d.cancel, the test would also
	// fail — but that's a real race we want to surface.
	waitSocket(t, ctrlSock)

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cancel()

	select {
	case err := <-runDone:
		if err != nil && err != context.Canceled {
			t.Fatalf("Run returned %v, want nil or context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon.Run did not return within 3s of Close — listener still blocking?")
	}
}

// TestBinaryStopsOnSIGINT builds the bidichan binary, runs it as a
// subprocess, sends SIGINT once we see it bound, and asserts it exits
// promptly. This catches end-to-end shutdown bugs that an in-process
// daemon test would miss (signal plumbing, runDaemon's handler, etc.).
func TestBinaryStopsOnSIGINT(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "bidichan")
	build := exec.Command("go", "build", "-o", binPath, "github.com/torkve/bidichan")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// Pick a free port up front.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	ctrlSock := filepath.Join(t.TempDir(), "ctrl.sock")
	cmd := exec.Command(binPath,
		"listen",
		"--addr", addr,
		"--hostname", "example.test",
		"--psk", "aabbccdd",
		"--socket", ctrlSock,
	)
	// New process group so we can signal the bidichan process directly and
	// our SIGINT doesn't get intercepted by the go-test parent.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stderrR, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	logLines := make(chan string, 32)
	go func() {
		sc := bufio.NewScanner(stderrR)
		for sc.Scan() {
			line := sc.Text()
			logLines <- line
		}
		close(logLines)
	}()

	// Wait for the "listening on" log line — proves the listener is bound.
	waitForLog := func(needle string, d time.Duration) bool {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			select {
			case line, ok := <-logLines:
				if !ok {
					return false
				}
				if strings.Contains(line, needle) {
					return true
				}
			case <-time.After(time.Until(deadline)):
				return false
			}
		}
		return false
	}
	if !waitForLog("listening on", 5*time.Second) {
		_ = cmd.Process.Kill()
		t.Fatal("never saw \"listening on\" log line")
	}

	// Now SIGINT and wait for exit.
	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	select {
	case err := <-exited:
		dur := time.Since(start)
		if err != nil {
			// SIGINT exit code is 0 in our handler (cancel + clean shutdown),
			// so non-nil err here would indicate a problem.
			t.Fatalf("Wait returned %v after %v", err, dur)
		}
		if dur > 3*time.Second {
			t.Fatalf("binary took %v to exit — too slow", dur)
		}
		t.Logf("clean exit after %v", dur)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Signal(syscall.SIGQUIT) // dump goroutines
		time.Sleep(200 * time.Millisecond)
		_ = cmd.Process.Kill()
		t.Fatal("binary did not exit within 5s of SIGINT")
	}
}


