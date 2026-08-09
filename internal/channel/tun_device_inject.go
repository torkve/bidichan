//go:build ios || android

package channel

import (
	"errors"
	"sync"

	"github.com/torkve/bidichan/internal/peer"
)

// On iOS and Android there is no OS TUN device this process may open: the L3
// device belongs to the host, which adapts it to a TUNDevice and registers it
// here before opening a tun channel. On iOS that is the Packet Tunnel
// Provider's NEPacketTunnelFlow; on Android the file descriptor the system
// hands the app. water is not imported in either build.
var (
	tunFactoryMu sync.RWMutex
	tunFactory   func(spec peer.TUNSpec) (TUNDevice, error)
)

// SetTUNDeviceFactory registers the factory that produces the TUN device for
// each tun channel opened on a host-provided device. The mobile package calls
// this once at startup with a factory wrapping whatever the host supplied.
// Passing nil clears it. The (already sanitized) TUNSpec is passed so the factory can honor
// the negotiated MTU/CIDR when configuring the flow.
func SetTUNDeviceFactory(f func(spec peer.TUNSpec) (TUNDevice, error)) {
	tunFactoryMu.Lock()
	tunFactory = f
	tunFactoryMu.Unlock()
}

func newTUNDevice(spec peer.TUNSpec) (TUNDevice, error) {
	tunFactoryMu.RLock()
	f := tunFactory
	tunFactoryMu.RUnlock()
	if f == nil {
		return nil, errors.New("tun: no device factory registered (host must call channel.SetTUNDeviceFactory)")
	}
	return f(spec)
}
