//go:build !linux && !ios

package channel

import "github.com/songgao/water"

func applyLinuxName(cfg *water.Config, name string) {
	// Other platforms (e.g. macOS) ignore the name; the TUN/TAP layer assigns
	// one. The iOS build excludes this file entirely (no water dependency).
	_ = cfg
	_ = name
}
