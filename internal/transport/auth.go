package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

// We bind the auth HMAC to the TLS session via the "tls-unique" channel
// binding (RFC 5929) — the first Finished verify_data of the handshake.
// Both peers see the same 12 bytes and we mix them into the MAC so a
// passive observer who captures the upgrade request cannot replay it
// against a different TLS session.
//
// We initially used ExportKeyingMaterial, but uTLS's Chrome/Firefox
// ClientHello presets don't propagate the ekm setup through their custom
// handshake path (only HelloGolang does), so on the client side
// ExportKeyingMaterial returns "unavailable when renegotiation is
// enabled". TLSUnique is exposed correctly on both sides in TLS 1.2 with
// EMS, which is what gets negotiated here.

// computeAuthMAC returns the HMAC-SHA256 over (role || nonce || timestamp ||
// channel_binding), where role is "client" or "server". The two sides use
// different role bytes so the client MAC can never be replayed as the
// server's reply MAC (or vice versa). channel_binding is the TLS-unique
// value (RFC 5929) for the current TLS session — both peers compute the
// same bytes.
func computeAuthMAC(psk []byte, role string, nonce []byte, timestamp int64, binding []byte) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(role))
	mac.Write([]byte{0})
	mac.Write(nonce)
	mac.Write([]byte{0})
	var tsBuf [20]byte
	tsStr := strconv.AppendInt(tsBuf[:0], timestamp, 10)
	mac.Write(tsStr)
	mac.Write([]byte{0})
	mac.Write(binding)
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
