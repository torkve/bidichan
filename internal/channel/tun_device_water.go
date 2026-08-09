//go:build !ios && !android

package channel

import (
	"github.com/songgao/water"

	"github.com/torkve/bidichan/internal/peer"
)

// newTUNDevice creates a real OS TUN device via songgao/water. Used where this
// process may open one itself — Linux and macOS. The iOS and Android builds
// take the device from the host instead (see tun_device_inject.go). On Linux
// the device name from the (already sanitized) spec is applied; elsewhere the
// OS assigns it.
func newTUNDevice(spec peer.TUNSpec) (TUNDevice, error) {
	cfg := water.Config{DeviceType: water.TUN}
	if spec.Name != "" {
		applyLinuxName(&cfg, spec.Name)
	}
	ifce, err := water.New(cfg)
	if err != nil {
		return nil, err
	}
	return ifce, nil
}
