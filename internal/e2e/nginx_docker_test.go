package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// TestNginxDockerFront stands up a real nginx (in docker) terminating TLS in
// front of a bidichan plain-mode listener on a unix socket, and verifies:
//
//   - the bidichan client (uTLS) can complete the auth+upgrade through nginx
//   - a forward channel opens and round-trips bytes
//   - an unauthenticated HTTPS probe (no Upgrade header) gets the real nginx
//     default page, not our lookalike — because the front IS real nginx
//
// Requires docker, network access for the first nginx:alpine pull, and a
// kernel that lets us bind-mount a unix socket into a container. Skips
// otherwise.
func TestNginxDockerFront(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not in PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon unreachable")
	}

	share := t.TempDir()
	// Bind-mount target dir must be world-traversable so the container's
	// nginx worker (running as the `nginx` user inside the image) can chdir
	// into it. t.TempDir() defaults to 0700; loosen it.
	if err := os.Chmod(share, 0o755); err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM := mustGenCertPEM(t, "example.test")
	mustWrite(t, filepath.Join(share, "cert.pem"), certPEM, 0o644)
	mustWrite(t, filepath.Join(share, "key.pem"), keyPEM, 0o644)
	mustWrite(t, filepath.Join(share, "nginx.conf"), []byte(nginxConfTmpl), 0o644)

	// Start the bidichan listener on a unix socket inside the share dir so
	// nginx in the container can reach it via the bind mount. Plain mode =
	// no TLS, no binding.
	psk := mustPSK(t)
	sockPath := filepath.Join(share, "bidichan.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := log.New(io.Discard, "", 0)

	lis, err := transport.Listen(ctx, sockPath, transport.ServerConfig{
		Hostname: "example.test",
		PSK:      psk,
		Logger:   logger,
		Network:  "unix",
	})
	if err != nil {
		t.Fatalf("Listen plain: %v", err)
	}
	defer lis.Close()
	// Allow the container's nginx worker UID to connect.
	if err := os.Chmod(sockPath, 0o666); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	// One-peer accept loop.
	serverPeer := make(chan *peer.Peer, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := lis.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		p, err := peer.NewPeer(peer.RoleServer, c, "srv", logger)
		if err != nil {
			acceptErr <- err
			return
		}
		channel.Register(p)
		if err := p.Start(ctx); err != nil {
			acceptErr <- err
			return
		}
		serverPeer <- p
	}()

	// Run nginx in docker with the share dir bind-mounted RW so the worker
	// can talk to the unix socket, and a random host port mapped to 443.
	containerName := fmt.Sprintf("bidichan-e2e-%d", time.Now().UnixNano())
	runArgs := []string{
		"run", "-d", "--rm",
		"--name", containerName,
		"-p", "127.0.0.1:0:443",
		"-v", share + ":/shared",
		"nginx:alpine",
		"nginx", "-c", "/shared/nginx.conf", "-g", "daemon off;",
	}
	idBytes, err := exec.Command("docker", runArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, idBytes)
	}
	containerID := strings.TrimSpace(string(idBytes))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})

	hostPort := waitForPort(t, containerID)

	// Sanity: an unauthenticated HTTPS probe to / hits real nginx and gets
	// the location-/ body we configured — confirming the front-of-house is
	// genuinely nginx.
	{
		tlsClient := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "example.test",
				},
			},
		}
		url := fmt.Sprintf("https://127.0.0.1:%d/", hostPort)
		resp, err := tlsClient.Get(url)
		if err != nil {
			dumpNginxLogs(t, containerID)
			t.Fatalf("GET %s: %v", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "real nginx front") {
			dumpNginxLogs(t, containerID)
			t.Fatalf("expected real-nginx body at /, got: %q", body)
		}
		// And confirm the Server header is nginx.
		req, _ := http.NewRequest("HEAD", url, nil)
		hr, err := tlsClient.Do(req)
		if err != nil {
			t.Fatalf("HEAD /: %v", err)
		}
		if !strings.HasPrefix(strings.ToLower(hr.Header.Get("Server")), "nginx") {
			t.Fatalf("Server header not nginx: %q", hr.Header.Get("Server"))
		}
	}

	// Now the actual bidichan handshake: client dials 127.0.0.1:hostPort
	// (which is nginx), uTLS-Chrome-handshakes, sends Upgrade to /events,
	// nginx proxy_passes to our unix socket. We pass SkipBinding because
	// the TLS terminator (nginx) sits between us and the bidichan-server.
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	cliConn, err := transport.Dial(dialCtx, fmt.Sprintf("127.0.0.1:%d", hostPort), transport.ClientConfig{
		Hostname:           "example.test",
		PSK:                psk,
		InsecureSkipVerify: true,
		SkipBinding:        true,
	})
	if err != nil {
		dumpNginxLogs(t, containerID)
		t.Fatalf("Dial through nginx: %v", err)
	}
	cliP, err := peer.NewPeer(peer.RoleClient, cliConn, "cli", logger)
	if err != nil {
		t.Fatalf("client peer: %v", err)
	}
	channel.Register(cliP)
	if err := cliP.Start(ctx); err != nil {
		t.Fatalf("client start: %v", err)
	}
	defer cliP.Close()

	// Wait for the server side to register.
	var srvP *peer.Peer
	select {
	case srvP = <-serverPeer:
	case e := <-acceptErr:
		dumpNginxLogs(t, containerID)
		t.Fatalf("server accept: %v", e)
	case <-time.After(8 * time.Second):
		dumpNginxLogs(t, containerID)
		t.Fatal("server side never came up")
	}
	defer srvP.Close()

	// Forward channel: listen on the client, target an echo server.
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	openCtx, openCancel := context.WithTimeout(ctx, 5*time.Second)
	defer openCancel()
	if _, err := cliP.OpenChannel(openCtx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	}); err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}

	var listenAddr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && listenAddr == "" {
		for _, ch := range cliP.Snapshot() {
			if ch.Kind == peer.KindForward {
				listenAddr = extractListenAddr(ch.Description)
			}
		}
		if listenAddr == "" {
			time.Sleep(30 * time.Millisecond)
		}
	}
	if listenAddr == "" {
		t.Fatal("forward listener never appeared")
	}

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("hello-through-real-nginx")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}

// nginxConfTmpl is the test nginx config. It runs in foreground (-g
// "daemon off;"), terminates TLS for example.test with the provided
// cert/key, proxy_passes /events to the bidichan unix socket as a
// long-lived HTTP/1.1 Upgrade tunnel, and serves a recognisable body for
// any other location — what a normal nginx vhost would do.
const nginxConfTmpl = `
worker_processes 1;
events { worker_connections 64; }
http {
    upstream bidichan { server unix:/shared/bidichan.sock; }
    server {
        listen 443 ssl;
        server_name example.test;
        ssl_certificate     /shared/cert.pem;
        ssl_certificate_key /shared/key.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;

        location = /events {
            proxy_pass http://bidichan;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 1d;
            proxy_send_timeout 1d;
        }
        location / {
            default_type text/plain;
            return 200 'real nginx front';
        }
    }
}
`

func mustGenCertPEM(t *testing.T, host string) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

// waitForPort polls `docker port` until it returns the host port mapped to
// 443/tcp, then dials that port to ensure nginx has finished starting.
func waitForPort(t *testing.T, containerID string) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var port int
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "port", containerID, "443/tcp").CombinedOutput()
		if err == nil {
			line := strings.TrimSpace(string(out))
			// Lines look like "0.0.0.0:32768" / "[::]:32768". Take first.
			if i := strings.Index(line, "\n"); i >= 0 {
				line = line[:i]
			}
			if i := strings.LastIndex(line, ":"); i >= 0 {
				if p, err := atoi(line[i+1:]); err == nil && p > 0 {
					port = p
					break
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if port == 0 {
		t.Fatalf("nginx never published a host port (container %s)", containerID)
	}
	// Docker's userland proxy accepts TCP on the host port immediately even
	// while nginx is still starting inside the container — a successful
	// TCP dial here doesn't mean the TLS terminator is up. Poll until a
	// real TLS handshake completes.
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		d := &net.Dialer{Timeout: 500 * time.Millisecond}
		raw, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test"})
			_ = tc.SetDeadline(time.Now().Add(500 * time.Millisecond))
			if err := tc.Handshake(); err == nil {
				_ = tc.Close()
				return port
			}
			_ = tc.Close()
		}
		time.Sleep(150 * time.Millisecond)
	}
	dumpNginxLogs(t, containerID)
	t.Fatalf("nginx port %d never completed a TLS handshake", port)
	return 0
}

func atoi(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}

func mustGet(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func dumpNginxLogs(t *testing.T, containerID string) {
	t.Helper()
	out, err := exec.Command("docker", "logs", containerID).CombinedOutput()
	if err != nil {
		t.Logf("docker logs failed: %v", err)
		return
	}
	t.Logf("--- nginx container logs ---\n%s", out)
}
