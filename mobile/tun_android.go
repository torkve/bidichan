//go:build android

package mobile

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/daemon"
	"github.com/torkve/bidichan/internal/peer"
)

// SocketProtector is implemented by the host so the tunnel's own connection can
// be kept out of the tunnel it provides. Android routes an app's traffic into
// the active tunnel by default, which would send our transport through
// ourselves; the system's answer is to mark the socket as exempt before it
// connects (VpnService.protect, the fixed platform name).
//
// Protect is called on every outbound dial — including the redials the
// transport makes by itself when the network moves — and must return false only
// when the socket genuinely could not be exempted.
type SocketProtector interface {
	Protect(fd int) bool
}

// Start dials the server described by cfg and blocks until the peer link is up
// (or the attempt fails).
//
// tunFD is the descriptor of the L3 device the system gave the host, or 0 when
// no tun channel will be used. Ownership passes to this client: the host must
// have detached it (ParcelFileDescriptor.detachFd) and must not close it
// afterwards. protector, when non-nil, keeps our own socket out of the tunnel.
func (c *Client) Start(cfg *Config, tunFD int, protector SocketProtector) error {
	registered := false
	register := func() {
		if tunFD > 0 {
			registerFDFactory(tunFD)
			registered = true
		}
	}
	tweak := func(dcfg *daemon.Config) {
		if protector != nil {
			dcfg.DialControl = protectControl(protector)
		}
	}
	onFail := func() {
		if tunFD > 0 {
			clearTUNDevice()
		}
	}
	err := c.start(cfg, tweak, register, onFail)
	// The configuration can be rejected before register ever runs, and by then
	// the host has already detached the descriptor and is no longer allowed to
	// close it. Nothing else holds it, so close it here or it keeps the device
	// open for the life of the process. Both callbacks run synchronously inside
	// start, so this needs no synchronisation.
	if err != nil && tunFD > 0 && !registered {
		_ = syscall.Close(tunFD)
	}
	return err
}

// SetTunFD points tun channels at a new device. The host calls it with a fresh
// descriptor before reopening a tun channel on a rebuilt session: a descriptor
// is handed out once and closed with the channel that used it, so a new session
// needs a new one. Ownership passes to this client. Passing 0 clears it.
func (c *Client) SetTunFD(fd int) {
	if fd <= 0 {
		clearTUNDevice()
		return
	}
	registerFDFactory(fd)
}

// protectControl adapts a SocketProtector to the dial hook the transport wants.
// syscall.RawConn cannot cross the gomobile boundary, so the conversion to a
// plain descriptor happens here rather than in the host's interface.
func protectControl(p SocketProtector) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		var ok bool
		if err := rc.Control(func(fd uintptr) { ok = p.Protect(int(fd)) }); err != nil {
			return fmt.Errorf("protect socket: %w", err)
		}
		if !ok {
			return errors.New("host refused to exempt the socket from the tunnel")
		}
		return nil
	}
}

// pendingTUN holds the descriptor the host handed us until a channel takes it.
// Ownership matters here in a way it does not on iOS: this is a bare
// descriptor, so nothing collects it if we simply drop the reference — it, and
// the device it holds open, would survive for the life of the process. Whoever
// replaces or clears the registration therefore has to close what was never
// claimed.
var pendingTUN struct {
	mu    sync.Mutex
	fd    int  // -1 when there is nothing to hand out
	taken bool // a channel has it, so it is no longer ours to close
}

func init() { pendingTUN.fd = -1 }

// registerFDFactory installs a factory that hands the descriptor to the first
// tun channel that asks for it, replacing (and closing) any descriptor still
// waiting. A descriptor cannot be reopened once closed, so it is surrendered
// exactly once; a second channel gets a clear error rather than a descriptor
// that is already in use.
func registerFDFactory(fd int) {
	pendingTUN.mu.Lock()
	releaseLocked()
	pendingTUN.fd = fd
	pendingTUN.taken = false
	pendingTUN.mu.Unlock()

	channel.SetTUNDeviceFactory(func(spec peer.TUNSpec) (channel.TUNDevice, error) {
		pendingTUN.mu.Lock()
		defer pendingTUN.mu.Unlock()
		if pendingTUN.fd < 0 || pendingTUN.taken {
			return nil, errors.New("tun: the device descriptor has already been used")
		}
		name := spec.Name
		if name == "" {
			name = "tun0"
		}
		dev, err := newFDDevice(pendingTUN.fd, name)
		if err != nil {
			// Wrapping failed, so nothing owns it now — close it here and let
			// the next attempt bring a fresh one rather than reporting a stale
			// "already used" for what is really a setup failure.
			releaseLocked()
			return nil, err
		}
		pendingTUN.taken = true
		return dev, nil
	})
}

// clearTUNDevice drops the registration and closes a descriptor no channel
// ever took.
func clearTUNDevice() {
	pendingTUN.mu.Lock()
	releaseLocked()
	pendingTUN.mu.Unlock()
	channel.SetTUNDeviceFactory(nil)
}

// releaseLocked closes an unclaimed descriptor. A claimed one belongs to the
// device that took it and is closed with the channel.
func releaseLocked() {
	if pendingTUN.fd >= 0 && !pendingTUN.taken {
		_ = syscall.Close(pendingTUN.fd)
	}
	pendingTUN.fd = -1
	pendingTUN.taken = false
}

// fdDevice is the host's L3 device seen as a channel.TUNDevice. The descriptor
// behaves exactly like a Linux tun device — one whole IP packet per read, one
// per write — so the channel's framing needs nothing special.
type fdDevice struct {
	f    *os.File
	name string
}

func newFDDevice(fd int, name string) (*fdDevice, error) {
	// Register the descriptor with the runtime poller before wrapping it.
	// Without this a blocked read pins an OS thread and, worse, cannot be
	// interrupted by Close — so tearing the tunnel down would hang instead of
	// returning. A tun descriptor is pollable, so this is always available.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("tun: set nonblocking: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, errors.New("tun: invalid device descriptor")
	}
	return &fdDevice{f: f, name: name}, nil
}

func (d *fdDevice) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *fdDevice) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *fdDevice) Close() error                { return d.f.Close() }
func (d *fdDevice) Name() string                { return d.name }
