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

// serveDecoy writes a plausible nginx response. If req is non-nil we honour the
// request method (HEAD vs GET) so the decoy responds correctly to a probe.
// The connection is closed after writing.
func serveDecoy(c net.Conn, req *http.Request) {
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
// auth. If they sent a parseable request we mimic nginx for that one request,
// then close. If they haven't sent anything yet (e.g. they finished the TLS
// handshake but immediately got bored), we still wait briefly for a request so
// our shape looks normal.
func serveDecoyAndDrain(c net.Conn, br *bufio.Reader, firstReq *http.Request) {
	if firstReq != nil {
		serveDecoy(c, firstReq)
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
	serveDecoy(c, req)
}

// requestLooksLikeUs returns true if the request carries our protocol marker
// in the form of a specific Upgrade token. We piggyback on the very standard
// HTTP Upgrade mechanism (the same mechanism WebSockets use) so the request
// shape is plausible to any inspector that decrypts the TLS layer.
func requestLooksLikeUs(req *http.Request) bool {
	if req == nil {
		return false
	}
	conn := strings.ToLower(req.Header.Get("Connection"))
	upg := strings.ToLower(req.Header.Get("Upgrade"))
	return strings.Contains(conn, "upgrade") && upg == upgradeToken
}
