//go:build linux

package channel

import "github.com/songgao/water"

func applyLinuxName(cfg *water.Config, name string) {
	cfg.PlatformSpecificParams = water.PlatformSpecificParams{
		Name: name,
	}
}
