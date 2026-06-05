package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDecoyProxiesToRealBackend checks the fallback path: a connection that
// fails auth/Host must reach the configured real backend, so an unauthenticated
// client sees the backend's genuine responses (e.g. a 404 for an unknown path)
// rather than a static welcome page served for every path.
func TestDecoyProxiesToRealBackend(t *testing.T) {
	const hostname = "vpn.example.com"

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, "real-home")
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := log.New(io.Discard, "", 0)

	lis, err := Listen(ctx, "127.0.0.1:0", ServerConfig{
		Hostname:     hostname,
		PSK:          testPSK(t),
		Logger:       logger,
		DecoyBackend: backendAddr,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	// Accept must run for connections to be handled; decoy connections never
	// surface here (handle() returns them as nil), so this just loops.
	go func() {
		for {
			if _, err := lis.Accept(ctx); err != nil {
				return
			}
		}
	}()

	// probe sends one HTTP request over TLS (failing our auth — no Upgrade) and
	// returns the decoy backend's response.
	probe := func(t *testing.T, path string) *http.Response {
		t.Helper()
		conn, err := tls.Dial("tcp", lis.Addr().String(), &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("ReadResponse for %s: %v", path, err)
		}
		return resp
	}

	t.Run("unknown path gets backend 404", func(t *testing.T) {
		resp := probe(t, "/this-does-not-exist")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (decoy should proxy to the real backend)", resp.StatusCode)
		}
	})

	t.Run("root gets backend page", func(t *testing.T) {
		resp := probe(t, "/")
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "real-home" {
			t.Fatalf("status=%d body=%q, want 200 'real-home'", resp.StatusCode, body)
		}
	})
}
