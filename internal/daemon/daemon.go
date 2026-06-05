package daemon

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// Daemon owns the long-running process: it either listens for incoming
// transport connections or dials out, manages the resulting peer(s), and
// exposes a local Unix socket so the CLI can introspect and operate on them.
type Daemon struct {
	cfg    Config
	logger *log.Logger

	mu    sync.RWMutex
	peers map[string]*peer.Peer

	ctrlLis net.Listener
	ctrlDir string

	wg sync.WaitGroup

	// cancelMu protects cancel from a race between Run (which writes it
	// after setting up its derived context) and Close (which calls it on
	// shutdown). Both can fire concurrently when a signal handler races
	// with daemon startup.
	cancelMu sync.Mutex
	cancel   context.CancelFunc
}

// Config describes how the daemon should be set up.
type Config struct {
	// Role and addresses for the transport.
	Mode       Mode
	BindAddr   string // for ModeListen
	RemoteAddr string // for ModeConnect
	Hostname   string
	PSK        []byte
	CertPath   string
	KeyPath    string

	// TransportNetwork is "tcp" (default) or "unix". When "unix" the listen
	// or connect side skips TLS — used for behind-nginx deployments where a
	// reverse proxy terminates TLS and forwards plain bytes to / from a
	// local unix socket.
	TransportNetwork string

	// DecoyBackend, when set on the listen side, proxies connections that fail
	// SNI/Host/auth to a real web backend ("host:port" or "unix:/path")
	// instead of serving the built-in static page.
	DecoyBackend string

	// Path overrides the WebSocket upgrade request path. Empty derives a
	// PSK-specific path. Both ends must agree (same PSK derives the same
	// default).
	Path string

	// SkipBinding tells the client side to omit the certificate channel
	// binding from the auth HMAC. Required when connecting to a server
	// that is behind a TLS-terminating reverse proxy (since we have no
	// shared TLS session with that server). Implied when
	// TransportNetwork=="unix" on the connect side.
	SkipBinding bool

	// CACert is an optional path to a PEM bundle the connect side verifies the
	// server certificate against, instead of the system trust store. Set it to
	// pin a self-signed certificate or a private CA. Empty uses system roots.
	CACert string

	// ControlSocket is the Unix socket path where the local CLI talks to us.
	// Defaults to $XDG_RUNTIME_DIR/bidichan-<pid>.sock or /tmp fallback.
	ControlSocket string

	// PIDFile is written so the CLI's auto-discovery can find a running
	// daemon. Optional.
	PIDFile string

	// Logger; default if nil.
	Logger *log.Logger
}

type Mode int

const (
	ModeListen Mode = iota
	ModeConnect
)

// New constructs a Daemon. It does not start any network activity.
func New(cfg Config) (*Daemon, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.ControlSocket == "" {
		dir := defaultRuntimeDir()
		cfg.ControlSocket = fmt.Sprintf("%s/bidichan-%d.sock", dir, os.Getpid())
	}
	return &Daemon{
		cfg:    cfg,
		logger: cfg.Logger,
		peers:  make(map[string]*peer.Peer),
	}, nil
}

// Run blocks until the daemon shuts down (via Close or fatal error).
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancelMu.Lock()
	d.cancel = cancel
	d.cancelMu.Unlock()
	defer cancel()

	if err := d.startCtrl(); err != nil {
		return fmt.Errorf("ctrl socket: %w", err)
	}

	if d.cfg.PIDFile != "" {
		_ = os.WriteFile(d.cfg.PIDFile, []byte(fmt.Sprintf("%d\n%s\n", os.Getpid(), d.cfg.ControlSocket)), 0o600)
		defer os.Remove(d.cfg.PIDFile)
	}

	switch d.cfg.Mode {
	case ModeListen:
		return d.runListen(ctx)
	case ModeConnect:
		return d.runConnect(ctx)
	default:
		return errors.New("unknown daemon mode")
	}
}

func (d *Daemon) runListen(ctx context.Context) error {
	if d.cfg.TransportNetwork == "unix" {
		_ = os.Remove(d.cfg.BindAddr) // remove stale socket
	}
	lis, err := transport.Listen(ctx, d.cfg.BindAddr, transport.ServerConfig{
		Hostname:     d.cfg.Hostname,
		PSK:          d.cfg.PSK,
		CertPath:     d.cfg.CertPath,
		KeyPath:      d.cfg.KeyPath,
		Logger:       d.logger,
		Network:      d.cfg.TransportNetwork,
		DecoyBackend: d.cfg.DecoyBackend,
		Path:         d.cfg.Path,
	})
	if err != nil {
		return err
	}
	defer lis.Close()
	if d.cfg.TransportNetwork == "unix" {
		// Loosen perms so a same-host nginx worker can reach the socket.
		_ = os.Chmod(d.cfg.BindAddr, 0o660)
	}
	d.logger.Printf("listening on %s (%s), hostname=%s", lis.Addr(), netLabel(d.cfg.TransportNetwork), d.cfg.Hostname)

	for {
		c, err := lis.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			if err := d.adoptPeer(ctx, c, peer.RoleServer); err != nil {
				d.logger.Printf("adopt peer: %v", err)
				_ = c.Close()
			}
		}()
	}
}

func (d *Daemon) runConnect(ctx context.Context) error {
	var rootCAs *x509.CertPool
	if d.cfg.CACert != "" {
		pem, err := os.ReadFile(d.cfg.CACert)
		if err != nil {
			return fmt.Errorf("read --cacert: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(pem) {
			return fmt.Errorf("--cacert %s: no certificates found", d.cfg.CACert)
		}
	}
	c, err := transport.Dial(ctx, d.cfg.RemoteAddr, transport.ClientConfig{
		Hostname:    d.cfg.Hostname,
		PSK:         d.cfg.PSK,
		RootCAs:     rootCAs,
		Network:     d.cfg.TransportNetwork,
		SkipBinding: d.cfg.SkipBinding,
		Path:        d.cfg.Path,
	})
	if err != nil {
		return err
	}
	if err := d.adoptPeer(ctx, c, peer.RoleClient); err != nil {
		_ = c.Close()
		return err
	}
	// Wait until shutdown.
	<-ctx.Done()
	return nil
}

func (d *Daemon) adoptPeer(ctx context.Context, conn net.Conn, role peer.Role) error {
	id, _ := randomID()
	p, err := peer.NewPeer(role, conn, id, d.logger)
	if err != nil {
		return err
	}
	channel.Register(p)
	if err := p.Start(ctx); err != nil {
		return err
	}
	d.mu.Lock()
	d.peers[id] = p
	d.mu.Unlock()
	d.logger.Printf("peer %s up (remote=%s local=%s role=%v)", id, p.RemoteAddr(), p.LocalAddr(), role)
	go func() {
		<-p.Done()
		d.mu.Lock()
		delete(d.peers, id)
		d.mu.Unlock()
		d.logger.Printf("peer %s down", id)
	}()
	return nil
}

// Close stops accepting new connections, tears down peers, removes the
// control socket, and unblocks Run. Safe to call multiple times and before
// Run has finished setting up its context.
func (d *Daemon) Close() error {
	d.cancelMu.Lock()
	cancel := d.cancel
	d.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if d.ctrlLis != nil {
		_ = d.ctrlLis.Close()
	}
	d.mu.Lock()
	for _, p := range d.peers {
		_ = p.Close()
	}
	d.mu.Unlock()
	if d.ctrlDir != "" {
		_ = os.Remove(d.cfg.ControlSocket)
	}
	d.wg.Wait()
	return nil
}

// Peers returns a snapshot of the current peer list.
func (d *Daemon) Peers() []*peer.Peer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*peer.Peer, 0, len(d.peers))
	for _, p := range d.peers {
		out = append(out, p)
	}
	return out
}

// PeerByID returns the peer for the given id, or nil.
func (d *Daemon) PeerByID(id string) *peer.Peer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.peers[id]
}

func randomID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func defaultRuntimeDir() string {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		return v
	}
	return os.TempDir()
}

func netLabel(n string) string {
	if n == "" {
		return "tcp"
	}
	return n
}

// touch ensures the daemon keeps imports consistent — used by tests.
var _ = time.Now
