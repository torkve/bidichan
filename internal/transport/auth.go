package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// upgradeToken is the protocol identifier carried in the HTTP Upgrade header.
// It only matters to someone who can decrypt the TLS layer; the network-level
// shape is just "HTTP/1.1 inside TLS 1.2", which is indistinguishable from a
// WebSocket handshake or any other HTTP-Upgrade-based service.
const upgradeToken = "bidichan/1"

// maxClockSkew is the largest tolerated difference between the timestamp in
// the client's auth header and the server's clock. Wide enough that ordinary
// NTP drift won't fail us, narrow enough that a recorded handshake won't
// replay tomorrow.
const maxClockSkew = 90 * time.Second

// exportLabel namespaces our TLS exporter so the keying material we derive
// cannot collide with any other protocol's exporter usage on the same key.
const exportLabel = "EXPERIMENTAL-bidichan-v1"

// deriveExporter returns 32 bytes of keying material bound to the current TLS
// session. We mix this into the auth HMAC so a passive observer who captures
// the ciphertext cannot replay it against a different TLS handshake later.
func deriveExporter(c *tls.Conn) ([]byte, error) {
	st := c.ConnectionState()
	return st.ExportKeyingMaterial(exportLabel, nil, 32)
}

// computeAuthMAC returns the HMAC-SHA256 over (role || nonce || timestamp ||
// exporter), where role is "client" or "server". The two sides use different
// role bytes so the client MAC can never be replayed as the server's reply
// MAC (or vice versa).
func computeAuthMAC(psk []byte, role string, nonce []byte, timestamp int64, exporter []byte) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(role))
	mac.Write([]byte{0})
	mac.Write(nonce)
	mac.Write([]byte{0})
	var tsBuf [20]byte
	tsStr := strconv.AppendInt(tsBuf[:0], timestamp, 10)
	mac.Write(tsStr)
	mac.Write([]byte{0})
	mac.Write(exporter)
	return hex.EncodeToString(mac.Sum(nil))
}

// freshNonce returns 16 random bytes hex-encoded for use as X-BC-Nonce.
func freshNonce() (string, []byte, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(b[:]), b[:], nil
}

// parseNonce decodes a hex-encoded nonce from the wire.
func parseNonce(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad nonce: %w", err)
	}
	if len(b) < 8 || len(b) > 64 {
		return nil, errors.New("nonce wrong size")
	}
	return b, nil
}

// constantTimeEqHex compares two hex strings in constant time after decoding.
// Length mismatch is a fast-fail, but the underlying bytes comparison runs in
// constant time so we don't leak via timing how many leading bytes matched.
func constantTimeEqHex(a, b string) bool {
	ab, err := hex.DecodeString(a)
	if err != nil {
		return false
	}
	bb, err := hex.DecodeString(b)
	if err != nil {
		return false
	}
	if len(ab) != len(bb) {
		return false
	}
	return hmac.Equal(ab, bb)
}
