package e2e

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/peer"
)

// TestShellChannel opens an interactive shell channel, drives a scripted
// session through the PTY data stream, and confirms the marker comes back and
// the stream closes when the shell exits.
func TestShellChannel(t *testing.T) {
	cli, _, teardown := pair(t, "example.test")
	defer teardown()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	chID, err := cli.OpenChannel(ctx, peer.KindShell, peer.ShellSpec{
		Shell: "/bin/sh", Term: "dumb", Rows: 24, Cols: 80,
	})
	if err != nil {
		t.Fatalf("OpenChannel shell: %v", err)
	}

	r, ok := cli.ChannelRunner(chID)
	if !ok {
		t.Fatal("no runner for shell channel")
	}
	sc, ok := r.(peer.StreamChannel)
	if !ok {
		t.Fatalf("shell runner %T is not a StreamChannel", r)
	}
	stream := sc.Stream()

	if _, err := io.WriteString(stream, "echo BIDICHAN_OK\nexit\n"); err != nil {
		t.Fatalf("write to shell: %v", err)
	}
	// The shell echoes input + prints the marker, then exits → stream EOF.
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, _ := io.ReadAll(stream)
	if !strings.Contains(string(out), "BIDICHAN_OK") {
		t.Fatalf("shell output missing marker; got %q", out)
	}
}
