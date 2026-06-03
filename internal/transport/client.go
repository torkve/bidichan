package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ClientConfig configures the dialing side. Hostname is used as both the SNI
// extension and the Host: header.
type ClientConfig struct {
	Hostname           string
	PSK                []byte
	InsecureSkipVerify bool

	// Network selects the transport. "" / "tcp" (default) dials TCP and
	// negotiates a uTLS Chrome-fingerprinted TLS 1.2 session. "unix" dials a
	// local unix socket and skips TLS — useful for testing the auth+mux
	// path against a plain-mode server.
	Network string

	// SkipBinding tells the client not to include the TLS-unique channel
	// binding in the auth HMAC. Set this when the server is behind a
	// TLS-terminating reverse proxy (e.g. nginx + proxy_pass) — bidichan
	// sees plain bytes there and has no shared TLS session with us, so
	// any binding we send would not match what the server expects.
	// Also implicitly set when Network=="unix" since there is no TLS to
	// derive a binding from.
	SkipBinding bool
}

// Dial opens a connection to addr and performs the auth handshake. The
// returned net.Conn is ready for multiplex framing.
func Dial(ctx context.Context, addr string, cfg ClientConfig) (net.Conn, error) {
	if len(cfg.PSK) == 0 {
		return nil, errors.New("transport: empty PSK")
	}
	if cfg.Hostname == "" {
		return nil, errors.New("transport: empty hostname")
	}
	network := cfg.Network
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "unix" {
		return nil, fmt.Errorf("transport: invalid network %q", network)
	}

	d := net.Dialer{}
	if network == "tcp" {
		d.KeepAlive = 30 * time.Second
	}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var (
		appConn net.Conn
		binding []byte
	)
	if network == "unix" {
		appConn = raw
	} else {
		// Use uTLS to mimic Chrome's ClientHello. Passive DPI relies on
		// JA3/JA4 over the ClientHello; Go's stdlib produces a
		// recognisable fingerprint, while HelloChrome_Auto matches the
		// current published Chrome build.
		tlsC := &utls.Config{
			ServerName:         cfg.Hostname,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			NextProtos:         []string{"http/1.1"},
		}
		uconn := utls.UClient(raw, tlsC, utls.HelloChrome_Auto)

		if dl, ok := ctx.Deadline(); ok {
			_ = uconn.SetDeadline(dl)
		} else {
			_ = uconn.SetDeadline(time.Now().Add(15 * time.Second))
		}
		if err := uconn.HandshakeContext(ctx); err != nil {
			_ = uconn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		appConn = uconn
		if !cfg.SkipBinding {
			binding = uconn.ConnectionState().TLSUnique
			if len(binding) == 0 {
				_ = uconn.Close()
				return nil, errors.New("tls binding unavailable (no EMS?)")
			}
		}
	}

	br, err := performClientAuth(appConn, cfg, binding)
	if err != nil {
		_ = appConn.Close()
		return nil, err
	}

	_ = appConn.SetDeadline(time.Time{})
	return newBufferedConn(appConn, br), nil
}

func performClientAuth(appConn net.Conn, cfg ClientConfig, binding []byte) (*bufio.Reader, error) {
	nonceHex, nonceBytes, err := freshNonce()
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ts := time.Now().Unix()
	mac := computeAuthMAC(cfg.PSK, "client", nonceBytes, ts, binding)

	req := "GET /events HTTP/1.1\r\n" +
		"Host: " + cfg.Hostname + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + upgradeToken + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Accept: */*\r\n" +
		"X-BC-Nonce: " + nonceHex + "\r\n" +
		"X-BC-Time: " + strconv.FormatInt(ts, 10) + "\r\n" +
		"Authorization: Bearer " + mac + "\r\n" +
		"\r\n"
	if _, err := io.WriteString(appConn, req); err != nil {
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReader(appConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("server rejected upgrade: status %d", resp.StatusCode)
	}

	serverMAC := resp.Header.Get("X-BC-Verify")
	if serverMAC == "" {
		return nil, errors.New("server omitted X-BC-Verify")
	}
	wantServerMAC := computeAuthMAC(cfg.PSK, "server", nonceBytes, ts, binding)
	if !constantTimeEqHex(wantServerMAC, serverMAC) {
		return nil, errors.New("server MAC mismatch")
	}

	return br, nil
}
