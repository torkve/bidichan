//go:build linux

package channel

import (
	"fmt"
	"os/exec"
)

// configureInterface assigns an IP/CIDR, sets the MTU, and brings the device up
// using `ip` on Linux. dev and cidr have already been validated by
// sanitizeTUNSpec before reaching here.
func configureInterface(dev, cidr string, mtu int) error {
	cmds := [][]string{
		{"ip", "link", "set", "dev", dev, "mtu", fmt.Sprintf("%d", mtu)},
		{"ip", "addr", "add", cidr, "dev", dev},
		{"ip", "link", "set", "dev", dev, "up"},
	}
	for _, c := range cmds {
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %w: %s", c, err, string(out))
		}
	}
	return nil
}
