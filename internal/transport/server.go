package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerConfig configures the listener side of the transport. Hostname must
// match the SNI the client presents and the Host: header inside the request;
// any mismatch results in the nginx decoy being served.
type ServerConfig struct {
	Hostname string
	PSK      []byte
	CertPath string
	KeyPath  string
	Logger   *log.Logger
}

// Listener wraps a net.Listener and a tls.Config. Accept returns an
// authenticated net.Conn whose stream is ready for multiplexing.
type Listener struct {
	cfg   ServerConfig
	inner net.Listener
	tlsC  *tls.Config

	mu     sync.Mutex
	closed bool

	seenNonces *nonceCache
}

// Listen sets up the TLS listener. The PSK must be non-empty.
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
	cert, err := LoadOrGenerateCert(cfg.CertPath, cfg.KeyPath, cfg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	tlsC := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		// CipherSuites left at Go defaults — those cover the same suites a
		// stock nginx on Ubuntu negotiates, so the ServerHello blends in.
		NextProtos: []string{"http/1.1"},
	}
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	inner, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		cfg:        cfg,
		inner:      inner,
		tlsC:       tlsC,
		seenNonces: newNonceCache(),
	}, nil
}

// Addr returns the bound TCP address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

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

// Accept blocks for an incoming TCP connection, performs TLS + auth, and
// returns an authenticated net.Conn ready for multiplexing. Decoy traffic is
// handled internally and does not surface as a connection here. Errors are
// returned only for failures that affect the listener itself (e.g. the
// underlying TCP listener closed). Individual handshake failures are logged
// and skipped.
func (l *Listener) Accept(ctx context.Context) (net.Conn, error) {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		// Hand off the TLS handshake + auth to a goroutine so a slow attacker
		// can't block accept() of legitimate peers behind them. We pipe
		// successful auths back over a per-call channel so we only return
		// one conn per Accept().
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
	defer func() {
		// Anything still open at this point belongs to the decoy path.
	}()

	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	tlsConn := tls.Server(raw, l.tlsC)
	if err := tlsConn.Handshake(); err != nil {
		l.cfg.Logger.Printf("transport: tls handshake failed from %s: %v", raw.RemoteAddr(), err)
		_ = tlsConn.Close()
		return
	}

	st := tlsConn.ConnectionState()
	if st.ServerName != l.cfg.Hostname {
		// SNI mismatch — pretend to be nginx and close.
		l.cfg.Logger.Printf("transport: rejecting %s: SNI %q != %q", raw.RemoteAddr(), st.ServerName, l.cfg.Hostname)
		br := bufio.NewReader(tlsConn)
		serveDecoyAndDrain(tlsConn, br, nil)
		return
	}

	_ = tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		l.cfg.Logger.Printf("transport: bad http request from %s: %v", raw.RemoteAddr(), err)
		_ = tlsConn.Close()
		return
	}

	if !strings.EqualFold(req.Host, l.cfg.Hostname) || !requestLooksLikeUs(req) {
		serveDecoyAndDrain(tlsConn, br, req)
		return
	}

	if err := l.verifyClientAuth(tlsConn, req); err != nil {
		l.cfg.Logger.Printf("transport: rejecting %s: auth %v", raw.RemoteAddr(), err)
		serveDecoyAndDrain(tlsConn, br, req)
		return
	}

	// Drain the request body if any (there shouldn't be one but be safe).
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<14))
		_ = req.Body.Close()
	}

	// Reply 101 Switching Protocols with our server-side MAC.
	if err := l.replySwitchingProtocols(tlsConn, req); err != nil {
		l.cfg.Logger.Printf("transport: write 101 failed: %v", err)
		_ = tlsConn.Close()
		return
	}

	// Clear deadlines for the long-lived multiplexed phase.
	_ = tlsConn.SetDeadline(time.Time{})

	conn := newBufferedConn(tlsConn, br)
	select {
	case out <- conn:
	default:
		// Listener stopped consuming. Close to avoid leak.
		_ = conn.Close()
	}
}

func (l *Listener) verifyClientAuth(tlsConn *tls.Conn, req *http.Request) error {
	tsStr := req.Header.Get("X-BC-Time")
	nonceStr := req.Header.Get("X-BC-Nonce")
	auth := req.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return errors.New("missing bearer")
	}
	clientMAC := strings.TrimPrefix(auth, prefix)

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("bad timestamp: %w", err)
	}
	if d := time.Since(time.Unix(ts, 0)); d > maxClockSkew || d < -maxClockSkew {
		return fmt.Errorf("stale timestamp (skew %v)", d)
	}
	nonce, err := parseNonce(nonceStr)
	if err != nil {
		return err
	}
	if !l.seenNonces.add(nonceStr, time.Now()) {
		return errors.New("nonce replay")
	}
	exporter, err := deriveExporter(tlsConn)
	if err != nil {
		return fmt.Errorf("tls exporter: %w", err)
	}
	want := computeAuthMAC(l.cfg.PSK, "client", nonce, ts, exporter)
	if !constantTimeEqHex(want, clientMAC) {
		return errors.New("mac mismatch")
	}
	return nil
}

func (l *Listener) replySwitchingProtocols(tlsConn *tls.Conn, req *http.Request) error {
	tsStr := req.Header.Get("X-BC-Time")
	nonceStr := req.Header.Get("X-BC-Nonce")
	ts, _ := strconv.ParseInt(tsStr, 10, 64)
	nonce, _ := parseNonce(nonceStr)

	exporter, err := deriveExporter(tlsConn)
	if err != nil {
		return err
	}
	serverMAC := computeAuthMAC(l.cfg.PSK, "server", nonce, ts, exporter)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: " + upgradeToken + "\r\n" +
		"Connection: Upgrade\r\n" +
		"X-BC-Verify: " + serverMAC + "\r\n" +
		"\r\n"
	_ = tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = io.WriteString(tlsConn, resp)
	return err
}

// bufferedConn wraps a tls.Conn together with the bufio.Reader we used during
// the HTTP handshake. Any bytes the client sent ahead of the body remain in
// the bufio buffer and we need to drain them through Read for the multiplex
// layer to see them.
type bufferedConn struct {
	*tls.Conn
	r *bufio.Reader
}

func newBufferedConn(c *tls.Conn, r *bufio.Reader) *bufferedConn {
	return &bufferedConn{Conn: c, r: r}
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
