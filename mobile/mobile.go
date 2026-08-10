//go:build ios || android

// Package mobile is the gomobile-bound mobile facade for the bidichan
// connect-side client. It embeds the same transport/peer/channel core the CLI
// uses, driven in-process (no control socket) so a host — an iOS Packet Tunnel
// Provider, or an Android tunnel service — can hold the long-lived peer
// connection and manage channels from Swift or Kotlin.
package mobile

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/torkve/bidichan/internal/daemon"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// Client is the host-facing handle to an embedded connect-side daemon. It is
// safe for concurrent use.
//
// A started client stays started. Losing the network does not end it: the
// transport underneath resumes the same session, so the peer, its channels and
// the connections inside them survive the outage. Only when the session cannot
// be resumed at all does the client build a new one, and it keeps trying until
// Stop is called — so AwaitDone returns on shutdown, not on every flap. The host
// follows what is happening through LinkObserver.
type Client struct {
	mu     sync.Mutex
	d      *daemon.Daemon
	cancel context.CancelFunc
	done   chan struct{}
	runErr error  // set once under mu before done is closed
	logger Logger // optional diagnostic sink; set via SetLogger before Start
	obs    LinkObserver
	closed bool // Stop was called; the supervisor must not start a new session
}

// LinkObserver is implemented on the Swift side to follow the connection
// without the tunnel having to be torn down and rebuilt. Every method is
// called from a background goroutine.
type LinkObserver interface {
	// OnLinkState reports the transport link: "up" when traffic is flowing,
	// "down" while the network is gone and the transport is redialing (the
	// session, its channels and their connections are stalled, not closed),
	// and "failed" when the session could not be resumed and everything above
	// the transport is about to be rebuilt.
	OnLinkState(state string)

	// OnSessionUp fires whenever a peer session is established. reestablished
	// is false for the first one and true for each one built after a session
	// was lost for good — the host must reopen its channels then, because the
	// new session starts empty.
	OnSessionUp(reestablished bool)
}

// NewClient returns an idle client. Call Start to connect.
func NewClient() *Client { return &Client{} }

// SetLogger installs a diagnostic log sink. Call it before Start; passing nil
// discards logs (the default).
func (c *Client) SetLogger(l Logger) {
	c.mu.Lock()
	c.logger = l
	c.mu.Unlock()
}

// SetLinkObserver installs the connection-state sink. Call it before Start;
// passing nil discards the notifications (the default).
//
// The parameter is not named `o`: the Android binding generates C in which the
// receiver is a local called `o`, and a parameter of that name collides with it
// and fails to compile.
func (c *Client) SetLinkObserver(observer LinkObserver) {
	c.mu.Lock()
	c.obs = observer
	c.mu.Unlock()
}

func (c *Client) observer() LinkObserver {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.obs
}

func (c *Client) reportLink(state string) {
	if o := c.observer(); o != nil {
		o.OnLinkState(state)
	}
}

// start is the platform-independent half of Start: it validates cfg, builds the
// daemon configuration, launches the supervisor and blocks until the first peer
// link is up or the attempt fails.
//
// Each platform wraps it with its own Start, because what a host must supply
// differs: iOS passes a packet flow it pumps itself, Android passes the
// descriptor of the device the system gave it plus the means to keep our own
// socket out of the tunnel.
//
// register installs whatever the host supplied, and runs only once the
// configuration has been accepted and this client is known to be startable —
// registering earlier would let a rejected Start replace the device a running
// client is already using. onFail runs if the first attempt never came up, so
// the platform wrapper can drop what it registered.
func (c *Client) start(cfg *Config, tweak func(*daemon.Config), register, onFail func()) error {
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
	if c.closed {
		c.mu.Unlock()
		return errors.New("client already stopped; build a new one")
	}
	if c.done != nil {
		c.mu.Unlock()
		return errors.New("already started")
	}
	if cfg.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.MemoryLimitMB) << 20)
	}
	if register != nil {
		register()
	}
	logger := newStdLogger(c.logger)

	ready := make(chan struct{})
	var readyOnce sync.Once
	dcfg := daemon.Config{
		Mode:         daemon.ModeConnect,
		RemoteAddr:   cfg.Addr,
		Hostname:     cfg.Hostname,
		PSK:          psk,
		Path:         cfg.Path,
		SkipBinding:  cfg.NoTLSBinding,
		RootCAs:      pool,
		HelloID:      fp,
		EmbedControl: true,
		Logger:       logger,
		ResumeGrace:  time.Duration(cfg.ResumeGraceSeconds) * time.Second,
		OnReady:      func() { readyOnce.Do(func() { close(ready) }) },
		OnLinkState: func(state transport.LinkState, err error) {
			if err != nil {
				logger.Printf("link %s: %v", state, err)
			}
			c.reportLink(state.String())
		},
	}
	if tweak != nil {
		tweak(&dcfg)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.cancel = cancel
	c.done = done
	c.runErr = nil
	c.mu.Unlock()

	go c.supervise(ctx, dcfg, done)

	select {
	case <-ready:
		if o := c.observer(); o != nil {
			o.OnSessionUp(false)
		}
		return nil
	case <-done:
		// The first attempt failed before the peer was ever up — a bad address,
		// a wrong PSK, a server that isn't there. Report it rather than
		// retrying behind the user's back, and reset so Start can be called
		// again.
		c.mu.Lock()
		startErr := c.runErr
		c.d = nil
		c.done = nil
		c.cancel = nil
		c.mu.Unlock()
		cancel()
		if onFail != nil {
			onFail()
		}
		if startErr == nil {
			startErr = errors.New("connection closed before ready")
		}
		return startErr
	}
}

// Reconnect pacing after a session has been lost outright. Short enough that a
// device coming back onto a network reconnects promptly, long enough that a
// server that is simply down is not hammered.
const (
	sessionRetryMin = time.Second
	sessionRetryMax = 30 * time.Second
)

// supervise keeps a peer session running for as long as the client is started.
// The transport rides out ordinary outages by itself, so this loop only deals
// with a session that is gone for good: it builds a new one, and tells the host
// each time it succeeds, because a new session starts with no channels and the
// host has to reopen them.
func (c *Client) supervise(ctx context.Context, dcfg daemon.Config, done chan struct{}) {
	defer close(done)

	signalFirstReady := dcfg.OnReady
	delay := sessionRetryMin

	for attempt := 1; ; attempt++ {
		reestablished := attempt > 1
		up := make(chan struct{})
		var once sync.Once
		dcfg.OnReady = func() {
			once.Do(func() { close(up) })
			if !reestablished {
				signalFirstReady()
				return
			}
			if o := c.observer(); o != nil {
				o.OnSessionUp(true)
			}
		}

		d, err := daemon.New(dcfg)
		if err != nil {
			c.setRunErr(err)
			return
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.d = d
		c.mu.Unlock()

		runErr := d.Run(ctx)
		_ = d.Close()

		cameUp := false
		select {
		case <-up:
			cameUp = true
		default:
		}

		c.mu.Lock()
		c.d = nil
		stopping := c.closed
		c.mu.Unlock()

		switch {
		case stopping || ctx.Err() != nil:
			c.setRunErr(nil)
			return
		case !cameUp && attempt == 1:
			// The first connection never came up — a wrong address, a wrong
			// PSK, a server that isn't there. Report that to Start rather than
			// retrying behind the user's back.
			c.setRunErr(runErr)
			return
		}

		if cameUp {
			// A session we had is gone: everything above the transport dies
			// with it, so say so plainly and start the backoff over.
			c.reportLink("failed")
			delay = sessionRetryMin
		}
		dcfg.Logger.Printf("session ended (%v); building a new one in %s", runErr, delay)

		select {
		case <-ctx.Done():
			c.setRunErr(nil)
			return
		case <-time.After(delay):
		}
		if delay *= 2; delay > sessionRetryMax {
			delay = sessionRetryMax
		}
	}
}

// setRunErr records why the client stopped, for AwaitDone to report.
func (c *Client) setRunErr(err error) {
	c.mu.Lock()
	c.runErr = err
	c.mu.Unlock()
}

// AwaitDone blocks until the client stops for good and returns the reason, if
// any. The host calls this on a background thread and tears its tunnel down
// when it returns.
//
// Not named Wait: the Android binding turns it into a Java method, and `wait`
// is already taken by java.lang.Object, where it is final.
func (c *Client) AwaitDone() error {
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
	d, err := c.daemon()
	if err != nil {
		return "", err
	}
	return string(d.ControlJSON([]byte(reqJSON))), nil
}

// daemon returns the running daemon, distinguishing "never started" from the
// brief gap while a lost session is being rebuilt — the caller can retry the
// latter.
func (c *Client) daemon() (*daemon.Daemon, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.d != nil {
		return c.d, nil
	}
	if c.done != nil && !c.closed {
		return nil, errors.New("reconnecting")
	}
	return nil, errors.New("not started")
}

// Stop tears the client down for good, including the supervisor that would
// otherwise keep rebuilding the session. Safe to call more than once.
func (c *Client) Stop() error {
	c.mu.Lock()
	d := c.d
	cancel := c.cancel
	c.d = nil
	c.cancel = nil
	c.closed = true
	c.mu.Unlock()
	clearTUNDevice()
	if cancel != nil {
		cancel()
	}
	if d != nil {
		return d.Close()
	}
	return nil
}

// NetworkChanged tells the transport that the device's network path has
// changed — the host knows this long before a socket on the old path times out.
// A resumable connection drops the dead socket and redials at once, so the
// session (and everything running over it) resumes in about a round trip
// instead of after an idle timeout. Safe to call at any time.
func (c *Client) NetworkChanged() {
	c.mu.Lock()
	d := c.d
	c.mu.Unlock()
	if d != nil {
		d.NetworkChanged()
	}
}

// singlePeer returns the client's one peer (the connect side has exactly one).
func (c *Client) singlePeer() (*peer.Peer, error) {
	d, err := c.daemon()
	if err != nil {
		return nil, err
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
