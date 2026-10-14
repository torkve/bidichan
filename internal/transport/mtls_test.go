package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const mtlsHost = "vpn.example.com"

// testCA is a throwaway CA that issues client certificates for a test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issuePEM returns a PEM client certificate and key signed by ca.
func (ca *testCA) issuePEM(t *testing.T, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func (ca *testCA) issue(t *testing.T, eku ...x509.ExtKeyUsage) *tls.Certificate {
	t.Helper()
	certPEM, keyPEM := ca.issuePEM(t, eku, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	c, err := ClientCertFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// issueUnchecked is issue without ClientCertFromPEM's checks, for presenting a
// certificate the client side would have refused to load.
func (ca *testCA) issueUnchecked(t *testing.T, eku ...x509.ExtKeyUsage) *tls.Certificate {
	t.Helper()
	certPEM, keyPEM := ca.issuePEM(t, eku, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

// countingWriter counts the log lines that mention a client certificate.
type countingWriter struct{ n atomic.Int32 }

func (w *countingWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "authenticated with client certificate") {
		w.n.Add(1)
	}
	return len(p), nil
}

// mtlsListener starts a listener requiring certificates from ca and accepts
// for the life of the test.
func mtlsListener(t *testing.T, ctx context.Context, ca *testCA, logs io.Writer) *Listener {
	t.Helper()
	lis, err := Listen(ctx, "127.0.0.1:0", ServerConfig{
		Hostname:     mtlsHost,
		PSK:          testPSK(t),
		Logger:       log.New(logs, "", 0),
		ClientCAs:    ca.pool,
		ResumeConfig: ResumeConfig{Grace: 10 * time.Second},
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept(ctx)
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c) }() // echo
		}
	}()
	return lis
}

func mtlsClientConfig(t *testing.T, lis *Listener, cert *tls.Certificate) ClientConfig {
	roots := x509.NewCertPool()
	roots.AddCert(lis.Certificate())
	return ClientConfig{
		Hostname:   mtlsHost,
		PSK:        testPSK(t),
		RootCAs:    roots,
		ClientCert: cert,
		ResumeConfig: ResumeConfig{
			Grace:  10 * time.Second,
			Logger: log.New(io.Discard, "", 0),
		},
	}
}

func TestMutualTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newTestCA(t, "client ca")
	logs := &countingWriter{}
	lis := mtlsListener(t, ctx, ca, logs)

	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	conn, err := Dial(dctx, lis.Addr().String(), mtlsClientConfig(t, lis, ca.issue(t, x509.ExtKeyUsageClientAuth)))
	if err != nil {
		t.Fatalf("Dial with a valid client certificate: %v", err)
	}
	_ = conn.Close()
	if logs.n.Load() != 1 {
		t.Fatalf("server logged %d client-certificate logins, want 1", logs.n.Load())
	}

	for name, cert := range map[string]*tls.Certificate{
		"no certificate":         nil,
		"certificate of another": newTestCA(t, "other ca").issue(t, x509.ExtKeyUsageClientAuth),
		"server-auth only":       ca.issueUnchecked(t, x509.ExtKeyUsageServerAuth),
	} {
		if conn, err := Dial(dctx, lis.Addr().String(), mtlsClientConfig(t, lis, cert)); err == nil {
			_ = conn.Close()
			t.Errorf("%s: Dial succeeded", name)
		} else if !strings.Contains(err.Error(), "tls") {
			t.Errorf("%s: err = %v, want a TLS handshake failure", name, err)
		}
	}
}

// Every redial of a resumable session is a full handshake, so each one has to
// present the certificate again; a server requiring one would otherwise
// refuse the reconnect.
func TestMutualTLSResumeRedialPresentsCert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := newTestCA(t, "client ca")
	logs := &countingWriter{}
	lis := mtlsListener(t, ctx, ca, logs)
	relay := newCuttableRelay(t, lis.Addr().String())

	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	conn, err := DialSession(dctx, relay.lis.Addr().String(), mtlsClientConfig(t, lis, ca.issue(t, x509.ExtKeyUsageClientAuth)))
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer conn.Close()

	// The client notices the cut when it next uses the link, redials, and the
	// echo comes back over the resumed session.
	relay.cut()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write after cut: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo after resume: %q, %v", buf, err)
	}
	if n := logs.n.Load(); n < 2 {
		t.Fatalf("server saw %d client-certificate handshakes, want a second one for the redial", n)
	}
}

func TestMutualTLSRefusedInPlainMode(t *testing.T) {
	_, err := Listen(context.Background(), t.TempDir()+"/s.sock", ServerConfig{
		Hostname:  mtlsHost,
		PSK:       testPSK(t),
		Logger:    log.New(io.Discard, "", 0),
		Network:   "unix",
		ClientCAs: newTestCA(t, "ca").pool,
	})
	if err == nil {
		t.Fatal("Listen accepted client CAs in plain mode")
	}
}

func TestClientCertFromPEMChecksValidity(t *testing.T) {
	ca := newTestCA(t, "ca")
	now := time.Now()
	certPEM, keyPEM := ca.issuePEM(t, nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := ClientCertFromPEM(certPEM, keyPEM); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired certificate: err = %v", err)
	}
	certPEM, keyPEM = ca.issuePEM(t, nil, now.Add(time.Hour), now.Add(2*time.Hour))
	if _, err := ClientCertFromPEM(certPEM, keyPEM); err == nil || !strings.Contains(err.Error(), "not valid until") {
		t.Errorf("future certificate: err = %v", err)
	}
	certPEM, keyPEM = ca.issuePEM(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := ClientCertFromPEM(certPEM, keyPEM); err == nil || !strings.Contains(err.Error(), "clientAuth") {
		t.Errorf("server-auth-only certificate: err = %v", err)
	}
	for _, eku := range [][]x509.ExtKeyUsage{nil, {x509.ExtKeyUsageAny}, {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}} {
		certPEM, keyPEM = ca.issuePEM(t, eku, now.Add(-time.Hour), now.Add(time.Hour))
		if _, err := ClientCertFromPEM(certPEM, keyPEM); err != nil {
			t.Errorf("EKU %v: %v", eku, err)
		}
	}
	_, otherKey := ca.issuePEM(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	certPEM, _ = ca.issuePEM(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := ClientCertFromPEM(certPEM, otherKey); err == nil {
		t.Error("accepted a certificate with someone else's key")
	}
}

// cuttableRelay forwards TCP to target and can drop every connection through
// it, which a resumable client sees as the network going away.
type cuttableRelay struct {
	lis   net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newCuttableRelay(t *testing.T, target string) *cuttableRelay {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &cuttableRelay{lis: lis}
	go func() {
		for {
			in, err := lis.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				continue
			}
			r.mu.Lock()
			r.conns = append(r.conns, in, out)
			r.mu.Unlock()
			go func() { _, _ = io.Copy(out, in); _ = out.Close() }()
			go func() { _, _ = io.Copy(in, out); _ = in.Close() }()
		}
	}()
	t.Cleanup(func() { _ = lis.Close(); r.cut() })
	return r
}

func (r *cuttableRelay) cut() {
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// A unix dial has no TLS to present a certificate in; carrying one there
// would look like mutual authentication while presenting nothing.
func TestClientCertRefusedOnUnixNetwork(t *testing.T) {
	cfg := ClientConfig{
		Hostname:   mtlsHost,
		PSK:        testPSK(t),
		Network:    "unix",
		ClientCert: newTestCA(t, "ca").issue(t, x509.ExtKeyUsageClientAuth),
	}
	if _, err := Dial(context.Background(), t.TempDir()+"/s.sock", cfg); err == nil || !strings.Contains(err.Error(), "needs TLS") {
		t.Fatalf("Dial over unix with a client certificate: err = %v", err)
	}
}
