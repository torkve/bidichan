package channel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/torkve/bidichan/internal/peer"
)

// ShellHandler implements peer.ChannelHandler for an interactive PTY-backed
// shell. The shell runs on the responder; the originator attaches its terminal
// over a single data stream. allow gates *accepting* an open (spawning a shell
// on this host); originating is always permitted.
type ShellHandler struct {
	allow bool
}

func (h *ShellHandler) HandleOpen(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage) (json.RawMessage, peer.ChannelRunner, error) {
	if !h.allow {
		return nil, nil, errors.New("shell not permitted (peer not started with --allow-shell)")
	}
	var spec peer.ShellSpec
	if err := json.Unmarshal(specRaw, &spec); err != nil {
		return nil, nil, fmt.Errorf("shell spec: %w", err)
	}
	path, args, err := resolveShell(spec.Shell)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(path, args...)
	// Pin HOME=/ so the shell doesn't try (and fail) to read startup files
	// under an inaccessible or nonexistent home — e.g. when the daemon runs as
	// a system user with ProtectHome=yes, which otherwise yields a noisy
	// "bash: /home/<user>/.bashrc: Permission denied" on every session.
	env := setEnv(os.Environ(), "HOME", "/")
	if spec.Term != "" {
		env = setEnv(env, "TERM", spec.Term)
	}
	cmd.Env = env
	rows, cols := spec.Rows, spec.Cols
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		return nil, nil, fmt.Errorf("start shell %s: %w", path, err)
	}
	pid := cmd.Process.Pid
	r := &shellRunner{
		chID:   chID,
		cmd:    cmd,
		ptmx:   ptmx,
		desc:   fmt.Sprintf("shell %s (pid %d)", path, pid),
		reaped: make(chan struct{}),
	}
	// Reap the process and unblock the bridge when the shell exits. Record how
	// it died so an abnormal exit (e.g. killed by the seccomp sandbox) isn't
	// silently swallowed — without this the bridge just sees EOF and the CLI
	// exits 0 with no clue. We classify purely from the wait status: our own
	// detach teardown kills with SIGKILL (see Close), so a SIGKILL is the
	// expected "client detached" case and isn't logged; anything else is the
	// shell's own fate and is logged + propagated as the channel close reason.
	go func() {
		werr := cmd.Wait()
		var reason string
		if killedBy(werr, syscall.SIGKILL) {
			reason = "detached by client"
		} else {
			reason = describeShellExit(werr)
			p.Logger().Printf("shell %s (pid %d) %s", path, pid, reason)
		}
		r.exitReason.Store(reason)
		close(r.reaped)
		_ = ptmx.Close()
	}()
	return nil, r, nil
}

func (h *ShellHandler) HandleOriginate(ctx context.Context, p *peer.Peer, chID uint64, _ json.RawMessage, _ json.RawMessage) (peer.ChannelRunner, error) {
	// The originator opens the single data stream; the control-socket handler
	// splices the CLI's terminal to it via the StreamChannel interface.
	s, err := p.OpenStream(chID, nil)
	if err != nil {
		return nil, fmt.Errorf("open shell stream: %w", err)
	}
	return &shellOriginRunner{stream: s}, nil
}

func (h *ShellHandler) HandleStream(ctx context.Context, p *peer.Peer, runner peer.ChannelRunner, stream net.Conn, _ json.RawMessage) error {
	sr, ok := runner.(*shellRunner)
	if !ok {
		_ = stream.Close()
		return errors.New("shell: unexpected runner type")
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(sr.ptmx, stream); done <- struct{}{} }() // client -> pty
	go func() { _, _ = io.Copy(stream, sr.ptmx); done <- struct{}{} }() // pty -> client
	<-done
	sr.Close()         // kill shell + close ptmx (unblocks the pty-side copy)
	_ = stream.Close() // unblocks the stream-side copy
	<-done
	// Wait for the reaper to classify the exit so the close reason is the
	// shell's actual fate, not a guess (the reaper fires promptly: either the
	// shell already exited, or sr.Close() just SIGKILLed it). Bounded so a
	// wedged Wait can't hang the channel teardown.
	reason := "shell ended"
	select {
	case <-sr.reaped:
		if v := sr.exitReason.Load(); v != nil {
			reason = v.(string)
		}
	case <-time.After(2 * time.Second):
	}
	_ = p.CloseChannelByID(sr.chID, reason)
	return nil
}

// shellRunner is the responder-side state: the spawned shell on a PTY.
type shellRunner struct {
	chID       uint64
	cmd        *exec.Cmd
	ptmx       *os.File
	desc       string
	closeOnce  sync.Once
	reaped     chan struct{} // closed once the reaper has stored exitReason
	exitReason atomic.Value  // string: how the shell exited (set by the reaper)
}

func (r *shellRunner) Resize(rows, cols uint16) error {
	return pty.Setsize(r.ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

func (r *shellRunner) Close() error {
	r.closeOnce.Do(func() {
		// Kill (SIGKILL) is also how the reaper recognises a detach vs a
		// self-exit, so don't change the signal here without updating that.
		if r.cmd != nil && r.cmd.Process != nil {
			_ = r.cmd.Process.Kill()
		}
		if r.ptmx != nil {
			_ = r.ptmx.Close()
		}
	})
	return nil
}

// describeShellExit renders an exec.Cmd.Wait() result as a short human string,
// flagging the seccomp case specially since the hardened systemd unit's
// SystemCallFilter is the most common cause of an instantly-dead shell.
func describeShellExit(err error) string {
	if err == nil {
		return "exited (status 0)"
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			sig := ws.Signal()
			if sig == syscall.SIGSYS {
				return "killed by SIGSYS — a syscall was blocked by the sandbox " +
					"(systemd SystemCallFilter / seccomp); see docs/systemd/bidichan@.service"
			}
			return fmt.Sprintf("killed by signal %s", sig)
		}
		return fmt.Sprintf("exited (status %d)", ee.ExitCode())
	}
	return fmt.Sprintf("wait error: %v", err)
}

// killedBy reports whether err is an exec failure from the process being
// terminated by the given signal.
func killedBy(err error, sig syscall.Signal) bool {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			return ws.Signaled() && ws.Signal() == sig
		}
	}
	return false
}

// setEnv returns env with KEY set to val, replacing any existing KEY entries
// (glibc getenv() honours the first occurrence, so appending a duplicate would
// not override — the old value must be removed).
func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	out := env[:0:0]
	for _, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+val)
}

func (r *shellRunner) Description() string { return r.desc }

// shellOriginRunner is the originator-side state: it just holds the data
// stream so the daemon control handler can bridge the local terminal to it.
type shellOriginRunner struct {
	stream net.Conn
}

func (r *shellOriginRunner) Stream() net.Conn    { return r.stream }
func (r *shellOriginRunner) Close() error        { return r.stream.Close() }
func (r *shellOriginRunner) Description() string { return "shell (interactive)" }

// resolveShell picks the shell to spawn: the originator's $SHELL first (if it
// exists and is executable on this host), then a built-in fallback list. The
// busybox entries are invoked as `busybox sh`.
func resolveShell(userShell string) (path string, args []string, err error) {
	type candidate struct {
		path string
		args []string
	}
	var cands []candidate
	if userShell != "" {
		cands = append(cands, candidate{userShell, nil})
	}
	cands = append(cands,
		candidate{"/usr/bin/bash", nil},
		candidate{"/bin/bash", nil},
		candidate{"/usr/bin/busybox", []string{"sh"}},
		candidate{"/bin/busybox", []string{"sh"}},
		candidate{"/bin/sh", nil},
	)
	for _, c := range cands {
		if isExecutableFile(c.path) {
			return c.path, c.args, nil
		}
	}
	return "", nil, errors.New("no usable shell found")
}

func isExecutableFile(path string) bool {
	fi, err := os.Stat(path) // follows symlinks
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}
