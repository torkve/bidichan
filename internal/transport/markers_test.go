package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestMarkersArePSKSpecific guards Track D: the request path and cookie names
// must derive from the PSK, so no constant literal identifies the protocol
// across deployments.
func TestMarkersArePSKSpecific(t *testing.T) {
	psk1 := testPSK(t)
	psk2 := append([]byte(nil), psk1...)
	psk2[0] ^= 0xff

	if derivePath(psk1) == derivePath(psk2) {
		t.Error("derivePath is not PSK-specific")
	}
	if authCookieName(psk1) == authCookieName(psk2) {
		t.Error("authCookieName is not PSK-specific")
	}
	if authCookieName(psk1) == verifyCookieName(psk1) {
		t.Error("auth and verify cookie names collide")
	}
	if !strings.HasPrefix(derivePath(psk1), "/") {
		t.Error("derived path must start with /")
	}
}

// TestProbeWithoutAuthCookieGetsDecoy checks that a well-formed WebSocket
// upgrade to the correct path but without a valid auth cookie is sent to the
// fallback (no 101) — a client that knows the path but not the PSK still gets
// the standard web response.
func TestProbeWithoutAuthCookieGetsDecoy(t *testing.T) {
	const hostname = "vpn.example.com"
	psk := testPSK(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lis, err := Listen(ctx, "127.0.0.1:0", ServerConfig{
		Hostname: hostname,
		PSK:      psk,
		Logger:   log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	go func() {
		for {
			if _, err := lis.Accept(ctx); err != nil {
				return
			}
		}
	}()

	conn, err := tls.Dial("tcp", lis.Addr().String(), &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Correct path + valid WebSocket shape, but no auth cookie.
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\n"+
		"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nConnection: close\r\n\r\n",
		derivePath(psk), hostname)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("server upgraded a connection with no valid auth cookie")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decoy status = %d, want 200 (static nginx page)", resp.StatusCode)
	}
}
