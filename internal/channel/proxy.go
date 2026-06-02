package channel

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/torkve/bidichan/internal/peer"
)

// ProxyKind selects HTTP or SOCKS5 frontends. The egress (dialing) side never
// cares which one is in use — it just receives a target host:port in the
// stream metadata and dials it.
type ProxyKind int

const (
	ProxyHTTP ProxyKind = iota
	ProxySOCKS5
)

// HTTPProxyHandler accepts CONNECT and absolute-URL HTTP proxy requests on
// the local side and tunnels them through to the peer for egress.
type HTTPProxyHandler struct{}

func (h *HTTPProxyHandler) HandleOpen(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage) (json.RawMessage, peer.ChannelRunner, error) {
	return setupProxy(ctx, p, chID, specRaw, ProxyHTTP, false)
}

func (h *HTTPProxyHandler) HandleOriginate(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage, _ json.RawMessage) (peer.ChannelRunner, error) {
	_, r, err := setupProxy(ctx, p, chID, specRaw, ProxyHTTP, true)
	return r, err
}

func (h *HTTPProxyHandler) HandleStream(ctx context.Context, p *peer.Peer, runner peer.ChannelRunner, stream net.Conn, metaRaw json.RawMessage) error {
	return serveEgress(stream, metaRaw)
}

// Socks5ProxyHandler is symmetric to HTTPProxyHandler.
type Socks5ProxyHandler struct{}

func (h *Socks5ProxyHandler) HandleOpen(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage) (json.RawMessage, peer.ChannelRunner, error) {
	return setupProxy(ctx, p, chID, specRaw, ProxySOCKS5, false)
}

func (h *Socks5ProxyHandler) HandleOriginate(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage, _ json.RawMessage) (peer.ChannelRunner, error) {
	_, r, err := setupProxy(ctx, p, chID, specRaw, ProxySOCKS5, true)
	return r, err
}

func (h *Socks5ProxyHandler) HandleStream(ctx context.Context, p *peer.Peer, runner peer.ChannelRunner, stream net.Conn, metaRaw json.RawMessage) error {
	return serveEgress(stream, metaRaw)
}

type proxyRunner struct {
	kind ProxyKind
	spec peer.ProxySpec
	role forwardRole

	lis       net.Listener
	closeOnce sync.Once
}

func (r *proxyRunner) Close() error {
	r.closeOnce.Do(func() {
		if r.lis != nil {
			_ = r.lis.Close()
		}
	})
	return nil
}

func (r *proxyRunner) Description() string {
	if r.role == roleListener {
		return fmt.Sprintf("%s proxy on %s -> egress via peer", r.kind, r.lis.Addr())
	}
	return fmt.Sprintf("%s proxy egress (frontend on peer at %s)", r.kind, r.spec.ListenAddr)
}

func setupProxy(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage, kind ProxyKind, originator bool) (json.RawMessage, peer.ChannelRunner, error) {
	var spec peer.ProxySpec
	if err := json.Unmarshal(specRaw, &spec); err != nil {
		return nil, nil, fmt.Errorf("proxy spec: %w", err)
	}
	weListen := whoListens(spec.ListenSide, originator)

	r := &proxyRunner{kind: kind, spec: spec}
	if !weListen {
		r.role = roleDialer
		return nil, r, nil
	}
	r.role = roleListener

	lis, err := net.Listen("tcp", spec.ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", spec.ListenAddr, err)
	}
	r.lis = lis
	go r.acceptLoop(ctx, p, chID)

	info, _ := json.Marshal(peer.AckInfoListener{BoundAddr: lis.Addr().String()})
	return info, r, nil
}

func (r *proxyRunner) acceptLoop(ctx context.Context, p *peer.Peer, chID uint64) {
	for {
		c, err := r.lis.Accept()
		if err != nil {
			return
		}
		go r.handleFrontend(ctx, p, chID, c)
	}
}

func (r *proxyRunner) handleFrontend(ctx context.Context, p *peer.Peer, chID uint64, c net.Conn) {
	defer c.Close()
	switch r.kind {
	case ProxyHTTP:
		r.handleHTTPFrontend(ctx, p, chID, c)
	case ProxySOCKS5:
		r.handleSocks5Frontend(ctx, p, chID, c)
	}
}

// --- HTTP frontend ---

func (r *proxyRunner) handleHTTPFrontend(ctx context.Context, p *peer.Peer, chID uint64, c net.Conn) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		// CONNECT host:port — establish tunnel and forward bytes.
		target := req.Host
		s, err := p.OpenStream(chID, peer.ForwardStreamMeta{Target: target})
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer s.Close()
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		bridgeWithBuffered(c, br, s)
		return
	}
	// Absolute-URI proxy request. Build target host:port, forward request,
	// stream response.
	target := absoluteRequestTarget(req)
	if target == "" {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	s, err := p.OpenStream(chID, peer.ForwardStreamMeta{Target: target})
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer s.Close()

	// Strip the hop-by-hop "Proxy-*" headers and ensure the request line
	// becomes origin-form rather than absolute-form (RFC 7230 §5.3.2).
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(s); err != nil {
		return
	}
	bridgeWithBuffered(c, br, s)
}

func absoluteRequestTarget(req *http.Request) string {
	if req.URL == nil || req.URL.Host == "" {
		return ""
	}
	host := req.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		// No explicit port — default per scheme.
		port := "80"
		if strings.EqualFold(req.URL.Scheme, "https") {
			port = "443"
		}
		host = net.JoinHostPort(host, port)
	}
	return host
}

// --- SOCKS5 frontend ---
//
// We support only the no-auth method and CONNECT command — adequate for
// driving curl/SSH over a tunnel. UDP ASSOCIATE and BIND are out of scope.
func (r *proxyRunner) handleSocks5Frontend(ctx context.Context, p *peer.Peer, chID uint64, c net.Conn) {
	br := bufio.NewReader(c)

	// Greeting.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	nmethods := int(hdr[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// Pick no-auth if offered; else fail.
	chosen := byte(0xff)
	for _, m := range methods {
		if m == 0x00 {
			chosen = 0x00
			break
		}
	}
	if _, err := c.Write([]byte{0x05, chosen}); err != nil {
		return
	}
	if chosen == 0xff {
		return
	}

	// Request.
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 || reqHdr[1] != 0x01 /* CONNECT */ {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	atyp := reqHdr[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	s, err := p.OpenStream(chID, peer.ForwardStreamMeta{Target: target})
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer s.Close()

	// Success reply. Bound address is 0.0.0.0:0 — we don't expose the
	// egress side's local socket.
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	bridgeWithBuffered(c, br, s)
}

// --- shared egress (responder side) ---

func serveEgress(stream net.Conn, metaRaw json.RawMessage) error {
	defer stream.Close()
	var meta peer.ForwardStreamMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return fmt.Errorf("proxy meta: %w", err)
	}
	if meta.Target == "" {
		return errors.New("proxy stream missing target")
	}
	out, err := net.Dial("tcp", meta.Target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", meta.Target, err)
	}
	defer out.Close()
	pipeBoth(stream, out)
	return nil
}

// bridgeWithBuffered copies bytes in both directions like pipeBoth but the
// frontend reader is wrapped in bufio (because we used it to parse the
// request) — we need to drain whatever is already buffered first.
func bridgeWithBuffered(frontend net.Conn, frontendR *bufio.Reader, backend net.Conn) {
	type readerConn struct {
		net.Conn
		r io.Reader
	}
	wrapped := &readerConn{Conn: frontend, r: io.MultiReader(frontendR, frontend)}
	pipeBoth(stickyReader{Conn: frontend, r: wrapped.r}, backend)
}

// stickyReader exposes a net.Conn whose Read goes through r (typically a
// MultiReader fronting a bufio buffer) while writes/closes still hit the
// underlying conn.
type stickyReader struct {
	net.Conn
	r io.Reader
}

func (s stickyReader) Read(p []byte) (int, error) { return s.r.Read(p) }

func (k ProxyKind) String() string {
	switch k {
	case ProxyHTTP:
		return "http"
	case ProxySOCKS5:
		return "socks5"
	}
	return "?"
}
