package transport

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ServerConfig configures the listener side of the transport.
//
// In the default mode (Network=="tcp") we terminate TLS ourselves: SNI must
// match Hostname and the auth HMAC is bound to the server certificate's SPKI.
// In plain mode (Network=="unix") we skip TLS entirely — a reverse proxy such
// as nginx is expected to terminate TLS and forward the inner HTTP upgrade to
// our unix socket. Plain mode is the recommended deployment, so the TLS layer
// is served by the real reverse proxy.
type ServerConfig struct {
	Hostname string
	PSK      []byte
	CertPath string
	KeyPath  string
	Logger   *log.Logger

	// Network is "tcp" (default) or "unix". The Address passed to Listen is
	// interpreted accordingly.
	Network string

	// DecoyBackend, when non-empty, is a real web backend that connections
	// failing SNI/Host/auth are transparently proxied to, so an unauthenticated
	// client reaches a genuine site instead of a static page. Formats:
	// "host:port" (TCP) or "unix:/path/to.sock". Empty falls back to the
	// built-in static nginx page.
	DecoyBackend string

	// Path is the request path the WebSocket upgrade must target. Empty
	// derives a PSK-specific path (the default); set it to pin a fixed path
	// that matches a reverse-proxy location.
	Path string
}

// plainMode is true when the listener does not terminate TLS itself.
func (c ServerConfig) plainMode() bool { return c.Network == "unix" }

// Listener wraps a net.Listener and accepts authenticated peer connections.
type Listener struct {
	cfg   ServerConfig
	inner net.Listener
	tlsC  *tls.Config // nil in plain mode

	// binding is the SPKI channel binding for our certificate, mixed into the
	// auth MAC. Empty in plain mode (no TLS terminated here).
	binding []byte

	// cert is the leaf certificate the listener presents (nil in plain mode),
	// exposed via Certificate so a client can pin a self-signed cert.
	cert *x509.Certificate

	// path is the effective request path the WebSocket upgrade must target.
	path string

	mu     sync.Mutex
	closed bool

	seenNonces *nonceCache
}

// Listen sets up the listener. PSK and Hostname must be non-empty.
// The network argument is taken from cfg.Network (default "tcp").
func Listen(ctx context.Context, addr string, cfg ServerConfig) (*Listener, error) {
	if len(cfg.PSK) == 0 {
		return nil, errors.New("transport: empty PSK")
	}
	if cfg.Hostname == "" {
		return nil, errors.New("transport: empty hostname")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Network != "tcp" && cfg.Network != "unix" {
		return nil, fmt.Errorf("transport: invalid network %q", cfg.Network)
	}

	l := &Listener{
		cfg:        cfg,
		seenNonces: newNonceCache(),
	}
	l.path = cfg.Path
	if l.path == "" {
		l.path = derivePath(cfg.PSK)
	}
	cfg.Logger.Printf("transport: websocket upgrade path is %s", l.path)

	if !cfg.plainMode() {
		cert, err := LoadOrGenerateCert(cfg.CertPath, cfg.KeyPath, cfg.Hostname)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		l.tlsC = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			// CipherSuites only governs the TLS 1.2 fallback (Go does not
			// allow configuring 1.3 suites). A modern client offering 1.3
			// negotiates 1.3 and these are not used. Restrict the 1.2 set to
			// the AEAD ECDHE suites real nginx negotiates with modern clients
			// so the JA3S cipher slot stays plausible on the fallback path.
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			NextProtos: []string{"http/1.1"},
		}

		leaf := cert.Leaf
		if leaf == nil {
			leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("parse leaf cert: %w", err)
			}
		}
		l.binding = spkiBinding(leaf)
		l.cert = leaf
	}

	var lc net.ListenConfig
	if cfg.Network == "tcp" {
		// Use a jittered keepalive interval per connection.
		lc.KeepAlive = randDuration(20*time.Second, 40*time.Second)
	}
	inner, err := lc.Listen(ctx, cfg.Network, addr)
	if err != nil {
		return nil, err
	}
	l.inner = inner

	// net.Listener.Accept() is a blocking syscall that does not watch ctx
	// — without this goroutine, Accept stays blocked on a quiet port and
	// the daemon hangs on SIGINT until the inner socket eventually errors
	// out (which, on a TCP listener with no pending conns, is "never").
	// Wire ctx cancellation to a Close on the listener so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	return l, nil
}

// Addr returns the bound network address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Certificate returns the leaf certificate the listener presents, or nil in
// plain mode. A client can add this to a cert pool to pin a self-signed cert.
func (l *Listener) Certificate() *x509.Certificate { return l.cert }

// Close stops the listener.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.inner.Close()
}

// Accept blocks for an incoming connection, performs TLS (if applicable) +
// auth, and returns an authenticated net.Conn ready for multiplexing.
// Decoy traffic is handled internally and does not surface here.
func (l *Listener) Accept(ctx context.Context) (net.Conn, error) {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		ch := make(chan net.Conn, 1)
		go l.handle(raw, ch)
		select {
		case c := <-ch:
			if c == nil {
				continue // decoy / rejected
			}
			return c, nil
		case <-ctx.Done():
			_ = raw.Close()
			return nil, ctx.Err()
		}
	}
}

func (l *Listener) handle(raw net.Conn, out chan<- net.Conn) {
	defer close(out)

	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))

	var (
		appConn net.Conn
		binding []byte
	)
	if l.cfg.plainMode() {
		// No TLS — the reverse proxy already did it. The auth binding
		// can't be derived (no shared TLS session), so we proceed with an
		// empty binding. The client must also be configured to skip the
		// binding.
		appConn = raw
	} else {
		tlsConn := tls.Server(raw, l.tlsC)
		if err := tlsConn.Handshake(); err != nil {
			l.cfg.Logger.Printf("transport: tls handshake failed from %s: %v", raw.RemoteAddr(), err)
			_ = tlsConn.Close()
			return
		}
		st := tlsConn.ConnectionState()
		if st.ServerName != l.cfg.Hostname {
			l.cfg.Logger.Printf("transport: rejecting %s: SNI %q != %q", raw.RemoteAddr(), st.ServerName, l.cfg.Hostname)
			br := bufio.NewReader(tlsConn)
			l.serveDecoy(tlsConn, br, nil)
			return
		}
		appConn = tlsConn
		binding = l.binding
	}

	_ = appConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(appConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		l.cfg.Logger.Printf("transport: bad http request from %s: %v", raw.RemoteAddr(), err)
		_ = appConn.Close()
		return
	}

	if !strings.EqualFold(req.Host, l.cfg.Hostname) || req.URL.Path != l.path || !isWebSocketUpgrade(req) {
		l.serveDecoy(appConn, br, req)
		return
	}

	nonce, ts, err := l.verifyClientAuth(req, binding)
	if err != nil {
		l.cfg.Logger.Printf("transport: rejecting %s: auth %v", raw.RemoteAddr(), err)
		l.serveDecoy(appConn, br, req)
		return
	}

	if req.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<14))
		_ = req.Body.Close()
	}

	if err := l.replySwitchingProtocols(appConn, req, binding, nonce, ts); err != nil {
		l.cfg.Logger.Printf("transport: write 101 failed: %v", err)
		_ = appConn.Close()
		return
	}

	_ = appConn.SetDeadline(time.Time{})

	// Wrap the data phase in real RFC 6455 framing (server does not mask) so
	// the post-101 bytes are valid WebSocket frames, not raw yamux.
	conn := newWSConn(newBufferedConn(appConn, br), false, true)
	select {
	case out <- conn:
	default:
		_ = conn.Close()
	}
}

// verifyClientAuth checks the upgrade request's auth cookie and returns the
// nonce and timestamp it carried (needed to compute the server's reply MAC).
// binding may be nil for plain mode — both sides must agree, mismatch fails
// the MAC check.
func (l *Listener) verifyClientAuth(req *http.Request, binding []byte) ([]byte, int64, error) {
	c, err := req.Cookie(authCookieName(l.cfg.PSK))
	if err != nil {
		return nil, 0, errors.New("missing auth cookie")
	}
	nonce, ts, mac, err := decodeAuthPayload(c.Value)
	if err != nil {
		return nil, 0, fmt.Errorf("bad auth payload: %w", err)
	}
	if d := time.Since(time.Unix(ts, 0)); d > maxClockSkew || d < -maxClockSkew {
		return nil, 0, fmt.Errorf("stale timestamp (skew %v)", d)
	}
	nonceKey := base64.RawURLEncoding.EncodeToString(nonce)
	if !l.seenNonces.add(nonceKey, time.Now()) {
		return nil, 0, errors.New("nonce replay")
	}
	want := computeAuthMAC(l.cfg.PSK, "client", nonce, ts, binding)
	if !hmac.Equal(want, mac) {
		return nil, 0, errors.New("mac mismatch")
	}
	return nonce, ts, nil
}

func (l *Listener) replySwitchingProtocols(c net.Conn, req *http.Request, binding, nonce []byte, ts int64) error {
	serverMAC := computeAuthMAC(l.cfg.PSK, "server", nonce, ts, binding)
	verifyCookie := verifyCookieName(l.cfg.PSK) + "=" + base64.RawURLEncoding.EncodeToString(serverMAC)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(req.Header.Get("Sec-WebSocket-Key")) + "\r\n" +
		"Set-Cookie: " + verifyCookie + "; Path=/; HttpOnly\r\n" +
		"\r\n"
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := io.WriteString(c, resp)
	return err
}

// bufferedConn wraps an application-layer conn together with the bufio.Reader
// we used during the HTTP handshake. Any bytes the peer sent ahead of the
// body remain in the bufio buffer and we need to drain them through Read for
// the multiplex layer to see them. The underlying conn is held as a net.Conn
// so the stdlib server (*tls.Conn), the uTLS client (*utls.UConn), and the
// plain unix conn can all be wrapped uniformly.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufferedConn(c net.Conn, r *bufio.Reader) *bufferedConn {
	return &bufferedConn{Conn: c, r: r}
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite forwards a half-close to the underlying conn when supported.
// Both *tls.Conn and *utls.UConn implement CloseWrite via their embedded
// TCP conn, and *net.UnixConn implements it natively, so the forwarding
// loops can half-close one direction without tearing down the whole stream.
func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}
