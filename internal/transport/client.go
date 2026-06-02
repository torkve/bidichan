package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// ClientConfig configures the dialing side. Hostname is used as both the SNI
// extension and the Host: header — they must match what the server expects.
type ClientConfig struct {
	Hostname           string
	PSK                []byte
	InsecureSkipVerify bool
}

// Dial opens a TCP+TLS connection to addr and performs the auth handshake.
// Returns a net.Conn ready for multiplex framing.
func Dial(ctx context.Context, addr string, cfg ClientConfig) (net.Conn, error) {
	if len(cfg.PSK) == 0 {
		return nil, errors.New("transport: empty PSK")
	}
	if cfg.Hostname == "" {
		return nil, errors.New("transport: empty hostname")
	}
	d := net.Dialer{KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsC := &tls.Config{
		ServerName:         cfg.Hostname,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{"http/1.1"},
	}
	tlsConn := tls.Client(raw, tlsC)
	if dl, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(dl)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	br, err := performClientAuth(tlsConn, cfg)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	_ = tlsConn.SetDeadline(time.Time{})
	return newBufferedConn(tlsConn, br), nil
}

func performClientAuth(tlsConn *tls.Conn, cfg ClientConfig) (*bufio.Reader, error) {
	exporter, err := deriveExporter(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("tls exporter: %w", err)
	}
	nonceHex, nonceBytes, err := freshNonce()
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ts := time.Now().Unix()
	mac := computeAuthMAC(cfg.PSK, "client", nonceBytes, ts, exporter)

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
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReader(tlsConn)
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
	wantServerMAC := computeAuthMAC(cfg.PSK, "server", nonceBytes, ts, exporter)
	if !constantTimeEqHex(wantServerMAC, serverMAC) {
		return nil, errors.New("server MAC mismatch")
	}

	return br, nil
}
