//go:build !linux

package channel

import "github.com/songgao/water"

func applyLinuxName(cfg *water.Config, name string) {
	// Other platforms ignore the name; the TUN/TAP layer assigns one.
	_ = cfg
	_ = name
}
