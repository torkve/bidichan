package transport

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestIOSFingerprintHandshake confirms a client presenting the iOS uTLS
// ClientHello still completes the full handshake + PSK auth against an
// unmodified server, and that the data phase works. This is the wire-compat
// proof for the mobile client's Safari-family fingerprint: the server sees a
// standard peer regardless of which browser the ClientHello mimics.
func TestIOSFingerprintHandshake(t *testing.T) {
	const hostname = "vpn.example.com"
	psk := testPSK(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := log.New(io.Discard, "", 0)

	lis, err := Listen(ctx, "127.0.0.1:0", ServerConfig{
		Hostname: hostname,
		PSK:      psk,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, err := lis.Accept(ctx)
		accCh <- accepted{c, err}
	}()

	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	pool := x509.NewCertPool()
	pool.AddCert(lis.Certificate())
	conn, err := Dial(dctx, lis.Addr().String(), ClientConfig{
		Hostname: hostname,
		PSK:      psk,
		RootCAs:  pool,
		HelloID:  utls.HelloIOS_Auto,
	})
	if err != nil {
		t.Fatalf("Dial with iOS fingerprint: %v", err)
	}
	defer conn.Close()

	a := <-accCh
	if a.err != nil {
		t.Fatalf("Accept: %v", a.err)
	}
	defer a.conn.Close()

	// Data-phase round-trip proves the WebSocket + auth path completed under the
	// iOS fingerprint, not just the TLS handshake.
	msg := []byte("hello over an ios fingerprint")
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(msg)
		writeErr <- err
	}()
	_ = a.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(a.conn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("data round-trip: got %q, want %q", got, msg)
	}
}

// TestUserAgentMatchesFingerprint guards the invariant that the HTTP
// User-Agent stays coherent with the TLS fingerprint: an iOS/Safari JA3 must
// not ship a Chrome-on-Windows UA (which would itself be a fingerprinting tell).
func TestUserAgentMatchesFingerprint(t *testing.T) {
	if ua := userAgent(utls.HelloIOS_Auto); !strings.Contains(ua, "iPhone") {
		t.Errorf("iOS UA = %q, want it to mention iPhone", ua)
	}
	if ua := userAgent(utls.HelloSafari_Auto); !strings.Contains(ua, "Macintosh") || !strings.Contains(ua, "Safari") {
		t.Errorf("Safari UA = %q, want Macintosh Safari", ua)
	}
	// Default / Chrome and the zero value both yield the Chrome UA.
	if ua := userAgent(utls.HelloChrome_Auto); !strings.Contains(ua, "Chrome/") {
		t.Errorf("Chrome UA = %q, want Chrome", ua)
	}
	if ua := userAgent(utls.ClientHelloID{}); !strings.Contains(ua, "Chrome/") {
		t.Errorf("default UA = %q, want Chrome", ua)
	}
}
