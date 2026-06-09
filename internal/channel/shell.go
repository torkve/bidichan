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
	cmd.Env = os.Environ()
	if spec.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+spec.Term)
	}
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
	r := &shellRunner{
		chID: chID,
		cmd:  cmd,
		ptmx: ptmx,
		desc: fmt.Sprintf("shell %s (pid %d)", path, cmd.Process.Pid),
	}
	// Reap the process and unblock the bridge when the shell exits on its own.
	go func() {
		_ = cmd.Wait()
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
	_ = p.CloseChannelByID(sr.chID, "shell ended")
	return nil
}

// shellRunner is the responder-side state: the spawned shell on a PTY.
type shellRunner struct {
	chID      uint64
	cmd       *exec.Cmd
	ptmx      *os.File
	desc      string
	closeOnce sync.Once
}

func (r *shellRunner) Resize(rows, cols uint16) error {
	return pty.Setsize(r.ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

func (r *shellRunner) Close() error {
	r.closeOnce.Do(func() {
		if r.cmd != nil && r.cmd.Process != nil {
			_ = r.cmd.Process.Kill()
		}
		if r.ptmx != nil {
			_ = r.ptmx.Close()
		}
	})
	return nil
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
