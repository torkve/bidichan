package channel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/peer"
)

// fakeTUN is a TUNDevice driven by channels, standing in for a real OS tun or
// the iOS NEPacketTunnelFlow-backed device. Read hands out one queued packet per
// call (the one-packet-per-Read contract the tun framing relies on); Write
// records what the channel injected toward the device.
type fakeTUN struct {
	readCh    chan []byte
	written   chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		readCh:  make(chan []byte, 4),
		written: make(chan []byte, 4),
		closed:  make(chan struct{}),
	}
}

func (f *fakeTUN) Read(p []byte) (int, error) {
	select {
	case pkt := <-f.readCh:
		return copy(p, pkt), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeTUN) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case f.written <- b:
	case <-f.closed:
	}
	return len(p), nil
}

func (f *fakeTUN) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeTUN) Name() string { return "faketun" }

// TestTUNFraming verifies the tun data-plane framing in both directions: each
// IP packet is carried as a uint16 little-endian length prefix followed by the
// raw packet, one packet per frame. This is the exact contract an iOS
// PacketFlow adapter must preserve, so it guards the highest-risk seam of the
// mobile port.
func TestTUNFraming(t *testing.T) {
	// deviceEnd is what the tun channel pumps against; wireEnd stands in for the
	// yamux data stream to the peer.
	deviceEnd, wireEnd := net.Pipe()
	fake := newFakeTUN()
	r := &tunRunner{
		spec:   peer.TUNSpec{MTU: 1400},
		ifce:   fake,
		closed: make(chan struct{}),
	}
	go func() { _ = r.attachStream(deviceEnd) }()
	defer r.Close()

	// Direction TUN -> stream: a packet read from the device must appear on the
	// wire as [len_LE][packet].
	out := []byte{0x45, 0x00, 0x00, 0x1c, 0xde, 0xad, 0xbe, 0xef}
	fake.readCh <- out

	_ = wireEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(wireEnd, hdr[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	n := binary.LittleEndian.Uint16(hdr[:])
	if int(n) != len(out) {
		t.Fatalf("framed length = %d, want %d", n, len(out))
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(wireEnd, got); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	if !bytes.Equal(got, out) {
		t.Fatalf("framed packet = %x, want %x", got, out)
	}

	// Direction stream -> TUN: a framed packet on the wire must be written to the
	// device verbatim.
	in := []byte{0x45, 0x00, 0x00, 0x24, 0x01, 0x02, 0x03, 0x04, 0x05}
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], uint16(len(in)))
	_ = wireEnd.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := wireEnd.Write(lb[:]); err != nil {
		t.Fatalf("write frame header: %v", err)
	}
	if _, err := wireEnd.Write(in); err != nil {
		t.Fatalf("write frame body: %v", err)
	}
	select {
	case got := <-fake.written:
		if !bytes.Equal(got, in) {
			t.Fatalf("device write = %x, want %x", got, in)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for packet delivery to device")
	}
}
