package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// tcpPair returns two connected TCP conns over loopback.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2 := <-accepted
	if c2 == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { c1.Close(); c2.Close() })
	return c1, c2
}

// readRawFrame parses one (small, <126-byte) frame straight off the wire.
func readRawFrame(t *testing.T, r io.Reader) (opcode byte, masked bool, payload []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	opcode = h[0] & 0x0F
	masked = h[1]&0x80 != 0
	n := int(h[1] & 0x7F)
	if n >= 126 {
		t.Fatalf("test helper only handles payloads < 126 (got len byte %d)", n)
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			t.Fatalf("read mask: %v", err)
		}
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i&3]
		}
	}
	return opcode, masked, payload
}

// TestWSConnRoundTrip exercises framing, masking, and multi-Read reassembly of
// a payload large enough to use the 16-bit length form.
func TestWSConnRoundTrip(t *testing.T) {
	c1, c2 := tcpPair(t)
	client := newWSConn(c1, true, false)
	server := newWSConn(c2, false, false)

	payload := bytes.Repeat([]byte("yamux-bytes "), 100) // 1200 bytes

	// client -> server
	go func() { _, _ = client.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("client->server payload mismatch")
	}

	// server -> client
	go func() { _, _ = server.Write(payload) }()
	got2 := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got2); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatal("server->client payload mismatch")
	}
}

// TestWSClientFramesAreMaskedBinary checks that the bytes a client puts on the
// wire after the handshake are a well-formed RFC 6455 binary frame with the
// mask bit set, as the spec requires for client-to-server frames.
func TestWSClientFramesAreMaskedBinary(t *testing.T) {
	c1, c2 := tcpPair(t)
	client := newWSConn(c1, true, false)

	go func() { _, _ = client.Write([]byte("hello")) }()

	opcode, masked, payload := readRawFrame(t, c2)
	if opcode != wsOpBinary {
		t.Fatalf("opcode = 0x%x, want binary (0x2)", opcode)
	}
	if !masked {
		t.Fatal("client frame is not masked (RFC 6455 requires client->server masking)")
	}
	if string(payload) != "hello" {
		t.Fatalf("payload = %q, want \"hello\"", payload)
	}
}

// TestWSServerFramesAreUnmasked checks the server side does not mask (per RFC).
func TestWSServerFramesAreUnmasked(t *testing.T) {
	c1, c2 := tcpPair(t)
	server := newWSConn(c2, false, false)

	go func() { _, _ = server.Write([]byte("world")) }()

	opcode, masked, payload := readRawFrame(t, c1)
	if opcode != wsOpBinary || masked || string(payload) != "world" {
		t.Fatalf("got opcode=0x%x masked=%v payload=%q, want binary/unmasked/\"world\"", opcode, masked, payload)
	}
}

// TestWSPingAnswered checks an inbound ping is answered with a pong and not
// surfaced to the data stream.
func TestWSPingAnswered(t *testing.T) {
	c1, c2 := tcpPair(t)
	client := newWSConn(c1, true, false)
	server := newWSConn(c2, false, false)

	go func() {
		_ = client.writeFrame(wsOpPing, []byte("hi"))
		_, _ = client.Write([]byte("data"))
	}()

	got := make([]byte, 4)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != "data" {
		t.Fatalf("server surfaced %q, want \"data\" (ping must not reach the data stream)", got)
	}

	opcode, _, payload := readRawFrame(t, c1)
	if opcode != wsOpPong || string(payload) != "hi" {
		t.Fatalf("got opcode=0x%x payload=%q, want pong/\"hi\"", opcode, payload)
	}
}
