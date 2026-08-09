//go:build linux && !android

package channel

import (
	"fmt"
	"os/exec"
)

// configureInterface assigns the IPv4 and/or IPv6 address, sets the MTU, and
// brings the device up using `ip` on Linux. cidr/cidr6 have already been
// validated by sanitizeTUNSpec; either may be empty.
func configureInterface(dev, cidr, cidr6 string, mtu int) error {
	cmds := [][]string{
		{"ip", "link", "set", "dev", dev, "mtu", fmt.Sprintf("%d", mtu)},
	}
	if cidr != "" {
		cmds = append(cmds, []string{"ip", "addr", "add", cidr, "dev", dev})
	}
	if cidr6 != "" {
		cmds = append(cmds, []string{"ip", "-6", "addr", "add", cidr6, "dev", dev})
	}
	cmds = append(cmds, []string{"ip", "link", "set", "dev", dev, "up"})
	for _, c := range cmds {
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %w: %s", c, err, string(out))
		}
	}
	return nil
}
