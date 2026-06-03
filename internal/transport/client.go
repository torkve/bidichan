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
// extension and the Host: header — they must match what the server expects.
type ClientConfig struct {
	Hostname           string
	PSK                []byte
	InsecureSkipVerify bool
}

// Dial opens a TCP connection to addr, performs a TLS handshake whose
// ClientHello mimics a current Chrome build (via uTLS), then runs the
// HTTP/1.1 + PSK upgrade. The returned net.Conn is ready for multiplex
// framing.
//
// The Chrome ClientHello fingerprint matters here because passive DPI
// almost always inspects TLS handshakes via JA3/JA4 — Go's stdlib
// produces a recognisable fingerprint, so a stock client would stand out.
// HelloChrome_Auto rotates to the latest published Chrome and gives us a
// ClientHello indistinguishable from real browser traffic.
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

	// We do NOT clamp the version range to TLS 1.2 on the client. A real
	// Chrome offers TLS 1.3 + 1.2 in its ClientHello; the server (which
	// pins MaxVersion=TLS12) will negotiate down to 1.2, and the resulting
	// wire shape is exactly what a Chrome-to-old-nginx session looks like.
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

	br, err := performClientAuth(uconn, cfg)
	if err != nil {
		_ = uconn.Close()
		return nil, err
	}

	_ = uconn.SetDeadline(time.Time{})
	return newBufferedConn(uconn, br), nil
}

func performClientAuth(uconn *utls.UConn, cfg ClientConfig) (*bufio.Reader, error) {
	binding := uconn.ConnectionState().TLSUnique
	if len(binding) == 0 {
		return nil, errors.New("tls binding unavailable (no EMS?)")
	}
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
	if _, err := io.WriteString(uconn, req); err != nil {
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReader(uconn)
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
