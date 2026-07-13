//go:build ios

package channel

import (
	"errors"
	"sync"

	"github.com/torkve/bidichan/internal/peer"
)

// On iOS there is no OS TUN device to open: packets arrive from the Packet
// Tunnel Provider's NEPacketTunnelFlow, which the Swift side adapts to a
// TUNDevice and registers here before opening a tun channel. water is not
// imported in this build.
var (
	tunFactoryMu sync.RWMutex
	tunFactory   func(spec peer.TUNSpec) (TUNDevice, error)
)

// SetTUNDeviceFactory registers the factory that produces the TUN device for
// each tun channel opened on iOS. The mobile package calls this once at startup
// with a factory that wraps the Swift-provided NEPacketTunnelFlow. Passing nil
// clears it. The (already sanitized) TUNSpec is passed so the factory can honor
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
