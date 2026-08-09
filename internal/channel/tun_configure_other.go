//go:build !linux || android

package channel

// configureInterface is a no-op wherever this process does not own the device.
// On macOS the operator configures it out of band; on iOS and Android the host
// applies the addressing when it creates the device, from the same TUNSpec
// CIDR/MTU, so there is nothing to do in-process here.
func configureInterface(dev, cidr, cidr6 string, mtu int) error {
	return nil
}
