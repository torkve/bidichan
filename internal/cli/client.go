package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/torkve/bidichan/internal/daemon"
)

// CtrlClient talks to a daemon's local Unix control socket.
type CtrlClient struct {
	conn net.Conn
	r    *bufio.Reader
}

// DialCtrl connects to the daemon at sockPath. If sockPath is empty we try to
// auto-discover a running daemon socket in the runtime dir.
func DialCtrl(sockPath string) (*CtrlClient, error) {
	if sockPath == "" {
		p, err := autoDiscover()
		if err != nil {
			return nil, err
		}
		sockPath = p
	}
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("dial ctrl socket %s: %w", sockPath, err)
	}
	return &CtrlClient{conn: c, r: bufio.NewReader(c)}, nil
}

// Close releases the underlying socket.
func (c *CtrlClient) Close() error { return c.conn.Close() }

// Call sends a single request and reads the response. Each request is
// independent — we keep the connection open only briefly per call.
func (c *CtrlClient) Call(action string, args any) (json.RawMessage, error) {
	var argsRaw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		argsRaw = b
	}
	req := daemon.CtrlRequest{Action: action, Args: argsRaw}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	_ = c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var resp daemon.CtrlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Data, nil
}

// autoDiscover returns the path of the first bidichan socket it finds in the
// XDG runtime dir, or an error if zero or more than one exist.
func autoDiscover() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var matches []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "bidichan-") || !strings.HasSuffix(name, ".sock") {
			continue
		}
		full := filepath.Join(dir, name)
		// Make sure it's actually a socket and a daemon is live behind it.
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.Mode()&fs.ModeSocket == 0 {
			continue
		}
		// Try to connect briefly.
		c, err := net.DialTimeout("unix", full, 200*time.Millisecond)
		if err != nil {
			continue
		}
		_ = c.Close()
		matches = append(matches, full)
	}
	sort.Strings(matches)
	switch len(matches) {
	case 0:
		return "", errors.New("no running bidichan daemon socket found; pass --socket")
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("multiple bidichan daemon sockets found, pass --socket: %v", matches)
	}
}
