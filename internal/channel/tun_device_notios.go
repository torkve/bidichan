//go:build !ios

package channel

import (
	"github.com/songgao/water"

	"github.com/torkve/bidichan/internal/peer"
)

// newTUNDevice creates a real OS TUN device via songgao/water. Used on Linux
// and macOS; the iOS build supplies its own injected implementation (see
// tun_device_ios.go). On Linux the device name from the (already sanitized)
// spec is applied; on other platforms the name is assigned by the OS.
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
