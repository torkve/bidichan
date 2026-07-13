//go:build ios

package mobile

import (
	"io"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/peer"
)

// PacketFlow is implemented on the Swift side to bridge the Packet Tunnel
// Provider's NEPacketTunnelFlow. It exchanges whole L3 IP packets: exactly one
// packet per ReadPacket (blocking until one is available) and one per
// WritePacket. The one-packet-per-Read contract is essential — the tun channel
// frames each packet with a uint16 length prefix, so a Read that returned a
// partial packet, or several concatenated packets, would corrupt the stream.
type PacketFlow interface {
	// ReadPacket blocks until an outbound IP packet is available and returns
	// exactly that one packet. A non-nil error (e.g. the flow was closed) tears
	// the tun channel down.
	ReadPacket() ([]byte, error)
	// WritePacket injects one inbound IP packet toward the OS.
	WritePacket(p []byte) error
	// Close releases the flow.
	Close() error
}

// flowDevice adapts a Swift PacketFlow to channel.TUNDevice.
type flowDevice struct {
	flow PacketFlow
	name string
}

func (d *flowDevice) Read(p []byte) (int, error) {
	pkt, err := d.flow.ReadPacket()
	if err != nil {
		return 0, err
	}
	if len(pkt) > len(p) {
		// The tun channel reads into a buffer sized to the negotiated MTU; a
		// larger packet cannot be framed, so fail rather than truncate (which
		// would corrupt the inner IP packet). In practice the Packet Tunnel
		// Provider honors the MTU we set, so this should not happen.
		return 0, io.ErrShortBuffer
	}
	return copy(p, pkt), nil
}

func (d *flowDevice) Write(p []byte) (int, error) {
	// gomobile copies the byte slice across the Objective-C boundary, so passing
	// p directly is safe even though the tun channel reuses its write buffer.
	if err := d.flow.WritePacket(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *flowDevice) Close() error { return d.flow.Close() }
func (d *flowDevice) Name() string { return d.name }

// registerTUNFactory wires the Swift PacketFlow into the channel package's iOS
// TUN device factory, so every tun channel opened over this client pumps
// against the same flow.
func registerTUNFactory(flow PacketFlow) {
	channel.SetTUNDeviceFactory(func(spec peer.TUNSpec) (channel.TUNDevice, error) {
		name := spec.Name
		if name == "" {
			name = "tun0"
		}
		return &flowDevice{flow: flow, name: name}, nil
	})
}
