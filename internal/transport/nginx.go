package transport

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// nginxBody is the canonical "Welcome to nginx!" page served by Debian/Ubuntu
// nginx packages. Byte-for-byte identical to what apt-installed nginx ships.
const nginxBody = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

// serveDecoy routes a connection that failed SNI/Host/auth to a fallback
// response. When a real DecoyBackend is configured we transparently proxy the
// connection to it, so an unauthenticated client reaches a genuine site (e.g. a
// real 404 for unknown paths) instead of a static welcome page. Otherwise we
// fall back to the built-in static nginx page.
func (l *Listener) serveDecoy(c net.Conn, br *bufio.Reader, req *http.Request) {
	if l.cfg.DecoyBackend == "" {
		serveDecoyAndDrain(c, br, req)
		return
	}
	if err := proxyToDecoy(l.cfg.DecoyBackend, c, br, req); err != nil {
		l.cfg.Logger.Printf("transport: decoy proxy to %s failed: %v", l.cfg.DecoyBackend, err)
		// The connection may be half-consumed; best effort is to close it the
		// way a real backend would on an upstream error.
		_ = c.Close()
	}
}

// dialDecoy connects to the configured decoy backend. Spec is either
// "unix:/path/to.sock" or a TCP "host:port".
func dialDecoy(spec string) (net.Conn, error) {
	if path, ok := strings.CutPrefix(spec, "unix:"); ok {
		return net.DialTimeout("unix", path, 10*time.Second)
	}
	return net.DialTimeout("tcp", spec, 10*time.Second)
}

// proxyToDecoy splices the client connection to a real backend. Any request we
// already parsed (req) is replayed to the backend first; then bytes flow in
// both directions until either side closes, so keep-alive, arbitrary paths, and
// the backend's real status codes all pass through untouched.
func proxyToDecoy(spec string, c net.Conn, br *bufio.Reader, req *http.Request) error {
	backend, err := dialDecoy(spec)
	if err != nil {
		return err
	}
	defer backend.Close()
	defer c.Close()

	// The handshake set a short deadline; clear it so the proxied session can
	// live as long as a normal connection to the backend would.
	_ = c.SetDeadline(time.Time{})

	if req != nil {
		if err := req.Write(backend); err != nil {
			return err
		}
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(backend, br) // client -> backend
		if cw, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(c, backend) // backend -> client
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errc <- err
	}()
	<-errc
	return nil
}

// serveDecoyStatic writes a standard nginx response. If req is non-nil we
// honour the request method (HEAD vs GET) so the response is correct for the
// request. The connection is closed after writing.
func serveDecoyStatic(c net.Conn, req *http.Request) {
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer c.Close()

	method := "GET"
	if req != nil {
		method = req.Method
	}

	var body string
	if method != "HEAD" {
		body = nginxBody
	}

	hdr := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0 (Ubuntu)\r\n" +
		"Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n" +
		"Content-Type: text/html\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(nginxBody)) +
		"Connection: close\r\n" +
		"ETag: \"5e7f0e7c-264\"\r\n" +
		"Accept-Ranges: bytes\r\n" +
		"\r\n"

	_, _ = io.WriteString(c, hdr)
	if body != "" {
		_, _ = io.WriteString(c, body)
	}
}

// serveDecoyAndDrain handles a confirmed TLS connection from someone who failed
// auth. If they sent a parseable request we serve an nginx-style response for
// that one request, then close. If they haven't sent anything yet (e.g. they
// finished the TLS handshake but immediately got bored), we still wait briefly
// for a request before closing.
func serveDecoyAndDrain(c net.Conn, br *bufio.Reader, firstReq *http.Request) {
	if firstReq != nil {
		serveDecoyStatic(c, firstReq)
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	req, err := http.ReadRequest(br)
	if err != nil {
		// They never sent a real request — just close as nginx would on idle.
		_ = c.Close()
		return
	}
	// Drain any request body so the connection close looks normal.
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<20))
		_ = req.Body.Close()
	}
	serveDecoyStatic(c, req)
}

// isWebSocketUpgrade reports whether the request is a well-formed RFC 6455
// WebSocket upgrade. We run a genuine WebSocket handshake so that, to anyone
// who decrypts the TLS layer, the request is shaped exactly like an ordinary
// browser WebSocket upgrade. The PSK-derived path and auth cookie (checked
// elsewhere) are what actually distinguish our clients from real ones.
func isWebSocketUpgrade(req *http.Request) bool {
	if req == nil {
		return false
	}
	conn := strings.ToLower(req.Header.Get("Connection"))
	upg := strings.ToLower(req.Header.Get("Upgrade"))
	return strings.Contains(conn, "upgrade") && upg == "websocket" && req.Header.Get("Sec-WebSocket-Key") != ""
}
