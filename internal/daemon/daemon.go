package daemon

import (
	"context"
	"crypto/rand"
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

	wg     sync.WaitGroup
	cancel context.CancelFunc
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
	d.cancel = cancel
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
	lis, err := transport.Listen(ctx, d.cfg.BindAddr, transport.ServerConfig{
		Hostname: d.cfg.Hostname,
		PSK:      d.cfg.PSK,
		CertPath: d.cfg.CertPath,
		KeyPath:  d.cfg.KeyPath,
		Logger:   d.logger,
	})
	if err != nil {
		return err
	}
	defer lis.Close()
	d.logger.Printf("listening on %s, hostname=%s", lis.Addr(), d.cfg.Hostname)

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
	c, err := transport.Dial(ctx, d.cfg.RemoteAddr, transport.ClientConfig{
		Hostname:           d.cfg.Hostname,
		PSK:                d.cfg.PSK,
		InsecureSkipVerify: true,
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
// control socket, and unblocks Run.
func (d *Daemon) Close() error {
	if d.cancel != nil {
		d.cancel()
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

// touch ensures the daemon keeps imports consistent — used by tests.
var _ = time.Now
