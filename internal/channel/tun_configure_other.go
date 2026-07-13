//go:build !linux

package channel

// configureInterface is a no-op off Linux. On macOS the operator configures the
// device out of band; on iOS addressing is applied by the Packet Tunnel
// Provider via NEPacketTunnelNetworkSettings from the same TUNSpec CIDR/MTU, so
// there is nothing to do in-process here.
func configureInterface(dev, cidr string, mtu int) error {
	return nil
}
