package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"time"
)

// maxClockSkew is the largest tolerated difference between the timestamp in
// the client's auth payload and the server's clock. Wide enough that ordinary
// NTP drift won't fail us, narrow enough that a recorded handshake won't
// replay tomorrow.
const maxClockSkew = 90 * time.Second

// nonceLen is the random nonce size carried in the auth payload.
const nonceLen = 16

// authPayloadLen is the fixed size of the decoded auth cookie value:
// nonce || big-endian int64 timestamp || HMAC-SHA256.
const authPayloadLen = nonceLen + 8 + sha256.Size

// wsGUID is the RFC 6455 magic value used to derive Sec-WebSocket-Accept. We
// run a standard WebSocket handshake so the request is an ordinary WebSocket
// upgrade — no custom Upgrade token or bespoke headers.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// spkiBinding returns the channel-binding value mixed into the auth MAC: the
// SHA-256 of the server certificate's SubjectPublicKeyInfo (an SPKI pin,
// equivalent in spirit to RFC 5929 "tls-server-end-point"). Both peers compute
// the same 32 bytes — the client from the certificate the server presented,
// the server from its own loaded certificate — so a relay that terminates TLS
// with a different certificate derives a different binding and fails auth.
//
// We previously used the "tls-unique" binding (RFC 5929), which forced the
// session to TLS 1.2 because TLS 1.3 has no tls-unique value (so the session
// negotiated 1.2 even when the client offered 1.3). The RFC 9266 "tls-exporter" binding would work
// under 1.3, but uTLS's Chrome ClientHello path does not wire up
// ExportKeyingMaterial, so we bind to the certificate instead — which is
// version-agnostic and lets the server offer TLS 1.3.
func spkiBinding(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// deriveMarker returns a PSK-keyed HMAC over label, used to make the on-wire
// markers (request path, auth/verify cookie names) deployment-specific rather
// than fixed constants.
func deriveMarker(psk []byte, label string) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte(label))
	return m.Sum(nil)
}

// derivePath returns the PSK-derived request path used for the WebSocket
// upgrade. It looks like an opaque random path; both peers compute it from the
// shared PSK. Operators fronting with a reverse proxy point their location at
// this path (logged at startup, or set explicitly with the path option).
func derivePath(psk []byte) string {
	d := deriveMarker(psk, "bidichan/path/v1")
	return "/" + base64.RawURLEncoding.EncodeToString(d)[:24]
}

// authCookieName / verifyCookieName look like ordinary session cookies. The
// client carries its auth payload in authCookieName; the server returns its
// proof of knowledge of the PSK in a Set-Cookie for verifyCookieName.
func authCookieName(psk []byte) string {
	d := deriveMarker(psk, "bidichan/cookie/client/v1")
	return "sid_" + base64.RawURLEncoding.EncodeToString(d)[:16]
}

func verifyCookieName(psk []byte) string {
	d := deriveMarker(psk, "bidichan/cookie/server/v1")
	return "ssr_" + base64.RawURLEncoding.EncodeToString(d)[:16]
}

// wsAccept computes the RFC 6455 Sec-WebSocket-Accept response value for a
// given Sec-WebSocket-Key.
func wsAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte(wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// freshWSKey returns a random RFC 6455 Sec-WebSocket-Key (base64 of 16 bytes).
func freshWSKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// computeAuthMAC returns the HMAC-SHA256 over (role || nonce || timestamp ||
// channel_binding), where role is "client" or "server". The two sides use
// different role bytes so the client MAC can never be replayed as the server's
// reply MAC (or vice versa). channel_binding is the SPKI binding for the
// current TLS session (or empty in plain mode) — both peers compute the same
// bytes.
func computeAuthMAC(psk []byte, role string, nonce []byte, timestamp int64, binding []byte) []byte {
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
	return mac.Sum(nil)
}

// freshNonce returns nonceLen random bytes.
func freshNonce() ([]byte, error) {
	b := make([]byte, nonceLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// encodeAuthPayload packs nonce || big-endian timestamp || mac into the base64
// (raw-url) value carried in the auth cookie.
func encodeAuthPayload(nonce []byte, timestamp int64, mac []byte) string {
	buf := make([]byte, 0, authPayloadLen)
	buf = append(buf, nonce...)
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], uint64(timestamp))
	buf = append(buf, tb[:]...)
	buf = append(buf, mac...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// decodeAuthPayload reverses encodeAuthPayload.
func decodeAuthPayload(s string) (nonce []byte, timestamp int64, mac []byte, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, 0, nil, err
	}
	if len(raw) != authPayloadLen {
		return nil, 0, nil, errors.New("bad auth payload length")
	}
	nonce = raw[:nonceLen]
	timestamp = int64(binary.BigEndian.Uint64(raw[nonceLen : nonceLen+8]))
	mac = raw[nonceLen+8:]
	return nonce, timestamp, mac, nil
}
