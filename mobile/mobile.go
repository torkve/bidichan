//go:build ios

// Package mobile is the gomobile-bound iOS facade for the bidichan connect-side
// client. It embeds the same transport/peer/channel core the CLI uses, driven
// in-process (no control socket) so an iOS Packet Tunnel Provider can host the
// long-lived peer connection and manage channels from Swift.
package mobile

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/daemon"
	"github.com/torkve/bidichan/internal/peer"
)

// Client is the iOS-facing handle to an embedded connect-side daemon. It is safe
// for concurrent use.
type Client struct {
	mu     sync.Mutex
	d      *daemon.Daemon
	cancel context.CancelFunc
	done   chan struct{}
	runErr error // set once under mu before done is closed
}

// NewClient returns an idle client. Call Start to connect.
func NewClient() *Client { return &Client{} }

// Start dials the server described by cfg and blocks until the peer link is up
// (or the attempt fails). flow, when non-nil, backs any tun channel opened over
// this client with the Packet Tunnel Provider's NEPacketTunnelFlow; pass nil if
// no tun channel will be used.
func (c *Client) Start(cfg *Config, flow PacketFlow) error {
	if cfg == nil {
		return errors.New("nil config")
	}
	psk, err := hex.DecodeString(strings.TrimSpace(cfg.PSKHex))
	if err != nil {
		return fmt.Errorf("psk: %w", err)
	}
	if len(psk) == 0 {
		return errors.New("empty psk")
	}
	if cfg.Addr == "" || cfg.Hostname == "" {
		return errors.New("addr and hostname are required")
	}
	fp, err := fingerprintID(cfg.Fingerprint)
	if err != nil {
		return err
	}
	var pool *x509.CertPool
	if len(cfg.CACertPEM) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
			return errors.New("cacert: no certificates found in PEM")
		}
	}

	c.mu.Lock()
	if c.d != nil {
		c.mu.Unlock()
		return errors.New("already started")
	}
	if cfg.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.MemoryLimitMB) << 20)
	}
	if flow != nil {
		registerTUNFactory(flow)
	}

	ready := make(chan struct{})
	var readyOnce sync.Once
	d, err := daemon.New(daemon.Config{
		Mode:         daemon.ModeConnect,
		RemoteAddr:   cfg.Addr,
		Hostname:     cfg.Hostname,
		PSK:          psk,
		Path:         cfg.Path,
		SkipBinding:  cfg.NoTLSBinding,
		RootCAs:      pool,
		HelloID:      fp,
		EmbedControl: true,
		Logger:       log.New(io.Discard, "", 0),
		OnReady:      func() { readyOnce.Do(func() { close(ready) }) },
	})
	if err != nil {
		c.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.d = d
	c.cancel = cancel
	c.done = done
	c.runErr = nil
	c.mu.Unlock()

	go func() {
		runErr := d.Run(ctx)
		c.mu.Lock()
		c.runErr = runErr
		c.mu.Unlock()
		close(done)
	}()

	select {
	case <-ready:
		return nil
	case <-done:
		// Run exited before signalling ready → the connect failed. Reset so the
		// caller can retry, and surface the reason. Clear the TUN factory too so
		// we don't hold a reference to the now-unusable Swift PacketFlow.
		c.mu.Lock()
		startErr := c.runErr
		c.d = nil
		c.cancel = nil
		c.mu.Unlock()
		cancel()
		if flow != nil {
			channel.SetTUNDeviceFactory(nil)
		}
		if startErr == nil {
			startErr = errors.New("connection closed before ready")
		}
		return startErr
	}
}

// Wait blocks until the session ends (peer lost or Stop called) and returns the
// reason, if any. The Packet Tunnel Provider calls this on a background thread
// and tears the tunnel down when it returns.
func (c *Client) Wait() error {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	if done == nil {
		return errors.New("not started")
	}
	<-done
	c.mu.Lock()
	runErr := c.runErr
	c.mu.Unlock()
	return runErr
}

// Control sends one control request (JSON, same schema as the daemon control
// socket: {"action":"...","args":{...}}) and returns the JSON response
// ({"data":...} or {"error":...}). The Go error is non-nil only when the client
// is not started; action-level failures come back inside the JSON. Shell
// channels are opened via OpenShell, not through this method.
func (c *Client) Control(reqJSON string) (string, error) {
	c.mu.Lock()
	d := c.d
	c.mu.Unlock()
	if d == nil {
		return "", errors.New("not started")
	}
	return string(d.ControlJSON([]byte(reqJSON))), nil
}

// Stop tears the client down. Safe to call more than once.
func (c *Client) Stop() error {
	c.mu.Lock()
	d := c.d
	cancel := c.cancel
	c.d = nil
	c.cancel = nil
	c.mu.Unlock()
	channel.SetTUNDeviceFactory(nil)
	if cancel != nil {
		cancel()
	}
	if d != nil {
		return d.Close()
	}
	return nil
}

// singlePeer returns the client's one peer (the connect side has exactly one).
func (c *Client) singlePeer() (*peer.Peer, error) {
	c.mu.Lock()
	d := c.d
	c.mu.Unlock()
	if d == nil {
		return nil, errors.New("not started")
	}
	ps := d.Peers()
	if len(ps) == 0 {
		return nil, errors.New("no active peer")
	}
	return ps[0], nil
}

// OpenShell opens an interactive shell channel on the peer and returns a
// ShellSession bound to its data stream. term/rows/cols seed the remote PTY.
// The peer must have been started with --allow-shell or the open is refused.
func (c *Client) OpenShell(term string, rows, cols int) (*ShellSession, error) {
	p, err := c.singlePeer()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	chID, err := p.OpenChannel(ctx, peer.KindShell, peer.ShellSpec{
		Term: term, Rows: uint16(rows), Cols: uint16(cols),
	})
	if err != nil {
		return nil, err
	}
	runner, ok := p.ChannelRunner(chID)
	if !ok {
		return nil, errors.New("shell channel vanished")
	}
	sc, ok := runner.(peer.StreamChannel)
	if !ok {
		_ = p.CloseChannelByID(chID, "internal error")
		return nil, errors.New("shell channel has no stream")
	}
	return &ShellSession{p: p, chID: chID, stream: sc.Stream()}, nil
}

// ShellSession is the client end of an interactive shell channel. Feed it to a
// terminal emulator: Read to receive output, Write to send input, Resize on
// window changes, Close to end the session.
type ShellSession struct {
	p         *peer.Peer
	chID      uint64
	stream    net.Conn
	closeOnce sync.Once
}

// Read blocks until shell output is available and returns it (up to an internal
// chunk size). It returns a non-nil error when the shell ends.
func (s *ShellSession) Read() ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := s.stream.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// Write sends input bytes to the remote shell.
func (s *ShellSession) Write(data []byte) error {
	_, err := s.stream.Write(data)
	return err
}

// Resize forwards a terminal window-size change to the remote PTY.
func (s *ShellSession) Resize(rows, cols int) error {
	return s.p.SendChannelResize(s.chID, uint16(rows), uint16(cols))
}

// Close ends the shell session and tears the channel down.
func (s *ShellSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.p.CloseChannelByID(s.chID, "shell closed by client")
	})
	return nil
}
