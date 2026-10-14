package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// ClientCertFromPEM parses a client certificate and its private key for mutual
// TLS. A certificate outside its validity window is refused here, so a stale
// one fails at startup rather than on some later redial.
func ClientCertFromPEM(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf := c.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return nil, fmt.Errorf("parse client certificate: %w", err)
		}
		c.Leaf = leaf
	}
	if !AllowsClientAuth(leaf) {
		return nil, errors.New("client certificate is not usable for client authentication (its extended key usage lacks clientAuth)")
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("client certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("client certificate is not valid until %s", leaf.NotBefore.Format(time.RFC3339))
	}
	return &c, nil
}

// AllowsClientAuth reports whether a server verifying the way Go's (and
// nginx's) does would accept leaf as a client certificate: it carries no
// extended key usage at all, or one that includes clientAuth or any.
func AllowsClientAuth(leaf *x509.Certificate) bool {
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// LoadClientCert reads a client certificate and key from PEM files; see
// ClientCertFromPEM.
func LoadClientCert(certPath, keyPath string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return ClientCertFromPEM(certPEM, keyPEM)
}

// LoadOrGenerateCert returns a usable certificate for the given hostname.
// If certPath/keyPath are non-empty and exist, they are loaded; otherwise a
// self-signed ECDSA cert is generated in memory. A self-signed cert will not
// validate in a browser, but it still presents a normal TLS handshake, like
// any other HTTPS server that uses a self-signed certificate.
func LoadOrGenerateCert(certPath, keyPath, hostname string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		if _, err := os.Stat(certPath); err == nil {
			return tls.LoadX509KeyPair(certPath, keyPath)
		}
	}
	return generateSelfSigned(hostname)
}

func generateSelfSigned(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ecdsa keygen: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
