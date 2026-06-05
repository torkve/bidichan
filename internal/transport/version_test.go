package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func testPSK(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString("0011223344556677889900aabbccddeeff00112233445566778899aabbccddee")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNegotiatesTLS13 confirms the uTLS Chrome ClientHello completes the
// handshake in TLS 1.3 (the client offers 1.3, the server must not pin 1.2).
// It also confirms the SPKI channel binding is non-empty so auth is still
// bound to the server certificate.
func TestNegotiatesTLS13(t *testing.T) {
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

	if len(lis.binding) == 0 {
		t.Fatal("server SPKI binding is empty")
	}

	accepted := make(chan error, 1)
	go func() {
		_, err := lis.Accept(ctx)
		accepted <- err
	}()

	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	pool := x509.NewCertPool()
	pool.AddCert(lis.Certificate())
	conn, err := Dial(dctx, lis.Addr().String(), ClientConfig{
		Hostname: hostname,
		PSK:      psk,
		RootCAs:  pool,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := <-accepted; err != nil {
		t.Fatalf("Accept: %v", err)
	}

	ws, ok := conn.(*wsConn)
	if !ok {
		t.Fatalf("conn is %T, want *wsConn", conn)
	}
	bc, ok := ws.inner.(*bufferedConn)
	if !ok {
		t.Fatalf("ws.inner is %T, want *bufferedConn", ws.inner)
	}
	uconn, ok := bc.Conn.(*utls.UConn)
	if !ok {
		t.Fatalf("underlying conn is %T, want *utls.UConn", bc.Conn)
	}
	if v := uconn.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version = 0x%04x, want TLS 1.3 (0x%04x)", v, tls.VersionTLS13)
	}
}
