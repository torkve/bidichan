package transport

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ClientConfig configures the dialing side. Hostname is used as both the SNI
// extension and the Host: header.
type ClientConfig struct {
	Hostname string
	PSK      []byte

	// RootCAs, when non-nil, is the set of certificate authorities the client
	// verifies the server against instead of the system trust store. Set this
	// to pin a self-signed certificate or a private CA. When nil the system
	// roots are used; the server certificate is always verified (there is no
	// option to skip verification).
	RootCAs *x509.CertPool

	// Network selects the transport. "" / "tcp" (default) dials TCP and
	// negotiates a uTLS Chrome-compatible TLS session. "unix" dials a
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

	// Path is the request path for the WebSocket upgrade. Empty derives a
	// PSK-specific path (the default), matching what the server expects. Set
	// it explicitly to match a fixed reverse-proxy location.
	Path string

	// HelloID selects the uTLS ClientHello fingerprint to mimic. The zero
	// value keeps the default (current Chrome, ECH stripped) so the CLI is
	// unchanged; the mobile client sets it to utls.HelloIOS_Auto /
	// HelloSafari_Auto so an iPhone presents a Safari-family fingerprint
	// (and a matching User-Agent, see userAgent) rather than Chrome-on-iOS.
	HelloID utls.ClientHelloID
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
		// Use a jittered keepalive interval per connection.
		d.KeepAlive = randDuration(20*time.Second, 40*time.Second)
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
		// Use a current Chrome-compatible ClientHello (via uTLS) for broad
		// TLS interoperability, with the GREASE ECH extension removed (see
		// chromeNoECHSpec). The hello offers h2 in ALPN; the WebSocket tunnel
		// is HTTP/1.1, so the reverse proxy must serve this endpoint over
		// http/1.1 — as any HTTP/1.1 WebSocket endpoint does.
		tlsC := &utls.Config{
			ServerName: cfg.Hostname,
			RootCAs:    cfg.RootCAs,
		}
		uconn := utls.UClient(raw, tlsC, utls.HelloCustom)
		spec, err := helloSpec(clientHelloID(cfg))
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("build clienthello: %w", err)
		}
		if err := uconn.ApplyPreset(&spec); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("apply clienthello: %w", err)
		}

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
			cs := uconn.ConnectionState()
			if len(cs.PeerCertificates) == 0 {
				_ = uconn.Close()
				return nil, errors.New("no server certificate for channel binding")
			}
			binding = spkiBinding(cs.PeerCertificates[0])
		}
	}

	br, err := performClientAuth(appConn, cfg, binding)
	if err != nil {
		_ = appConn.Close()
		return nil, err
	}

	_ = appConn.SetDeadline(time.Time{})
	// Wrap the data phase in real RFC 6455 framing (client masks) so the
	// post-101 bytes are valid WebSocket frames, not raw yamux.
	return newWSConn(newBufferedConn(appConn, br), true, true), nil
}

// clientHelloID returns the uTLS fingerprint to mimic: the caller-selected
// HelloID, or the default (current Chrome) when unset. Kept in one place so
// the ClientHello spec and the User-Agent header stay consistent.
func clientHelloID(cfg ClientConfig) utls.ClientHelloID {
	if cfg.HelloID.Client != "" {
		return cfg.HelloID
	}
	return utls.HelloChrome_Auto
}

// helloSpec builds a uTLS ClientHello spec for the given fingerprint with the
// GREASE encrypted_client_hello (ECH) extension removed. Some networks and
// middleboxes mishandle the ECH extension; removing it improves connectivity,
// and bidichan always sends a cleartext SNI so the extension is unnecessary.
// Stripping the GREASE-ECH extension is harmless for fingerprints that don't
// carry one (iOS/Safari), so this is safe across HelloIDs.
func helloSpec(id utls.ClientHelloID) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return utls.ClientHelloSpec{}, err
	}
	kept := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		if _, isECH := ext.(*utls.GREASEEncryptedClientHelloExtension); isECH {
			continue
		}
		kept = append(kept, ext)
	}
	spec.Extensions = kept
	return spec, nil
}

// chromeNoECHSpec is the default fingerprint: current Chrome, ECH stripped.
func chromeNoECHSpec() (utls.ClientHelloSpec, error) {
	return helloSpec(utls.HelloChrome_Auto)
}

// userAgent returns an HTTP User-Agent consistent with the TLS fingerprint id.
// A Chrome JA3 paired with a Chrome UA is coherent; an iOS/Safari JA3 must not
// ship a Chrome-on-Windows UA, which would itself be a fingerprinting tell.
func userAgent(id utls.ClientHelloID) string {
	switch id.Client {
	case "iOS":
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) " +
			"AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
	case "Safari":
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
			"AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
	default:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	}
}

func performClientAuth(appConn net.Conn, cfg ClientConfig, binding []byte) (*bufio.Reader, error) {
	nonce, err := freshNonce()
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ts := time.Now().Unix()
	mac := computeAuthMAC(cfg.PSK, "client", nonce, ts, binding)

	wsKey, err := freshWSKey()
	if err != nil {
		return nil, fmt.Errorf("ws key: %w", err)
	}

	path := cfg.Path
	if path == "" {
		path = derivePath(cfg.PSK)
	}
	cookie := authCookieName(cfg.PSK) + "=" + encodeAuthPayload(nonce, ts, mac)

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + cfg.Hostname + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"User-Agent: " + userAgent(clientHelloID(cfg)) + "\r\n" +
		"Accept: */*\r\n" +
		"Cookie: " + cookie + "\r\n" +
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

	if resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(wsKey) {
		return nil, errors.New("bad Sec-WebSocket-Accept")
	}

	serverMAC, err := cookieMAC(resp.Cookies(), verifyCookieName(cfg.PSK))
	if err != nil {
		return nil, fmt.Errorf("server verify cookie: %w", err)
	}
	wantServerMAC := computeAuthMAC(cfg.PSK, "server", nonce, ts, binding)
	if !hmac.Equal(serverMAC, wantServerMAC) {
		return nil, errors.New("server MAC mismatch")
	}

	return br, nil
}

// cookieMAC extracts and base64-decodes the MAC carried in the named cookie.
func cookieMAC(cookies []*http.Cookie, name string) ([]byte, error) {
	for _, c := range cookies {
		if c.Name == name {
			b, err := base64.RawURLEncoding.DecodeString(c.Value)
			if err != nil {
				return nil, err
			}
			if len(b) != sha256.Size {
				return nil, errors.New("wrong MAC length")
			}
			return b, nil
		}
	}
	return nil, errors.New("missing cookie")
}
