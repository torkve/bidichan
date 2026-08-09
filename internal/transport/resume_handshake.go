package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
)

// Session resumption is negotiated inside the WebSocket upgrade rather than
// with an extra round trip on the data phase, so the connection looks exactly
// as it did before: one more cookie going out, one more Set-Cookie coming
// back, both with PSK-derived names and opaque values.
//
// A peer that does not implement resumption simply never sends these cookies
// and ignores the ones it receives, so old and new peers interoperate — they
// just fall back to a connection that dies with the network.

// resumeCookieName carries the client's resume request; resumeAckCookieName
// carries the server's answer. Both look like ordinary session cookies.
func resumeCookieName(psk []byte) string {
	d := deriveMarker(psk, "bidichan/cookie/resume/v1")
	return "rid_" + base64.RawURLEncoding.EncodeToString(d)[:16]
}

func resumeAckCookieName(psk []byte) string {
	d := deriveMarker(psk, "bidichan/cookie/resume-ack/v1")
	return "rst_" + base64.RawURLEncoding.EncodeToString(d)[:16]
}

// resumeRequest is what the client offers: the session it wants to continue
// and how many stream bytes of the server's output it has already received.
// A first connection sends a fresh ID and RecvSeq 0.
type resumeRequest struct {
	ID      ResumeID
	RecvSeq uint64
}

const resumeRequestLen = resumeIDLen + 8

// bytes is the canonical encoding, also fed to the auth MAC. Because the
// layout is fixed-length, re-encoding a decoded request reproduces exactly the
// bytes the peer signed.
func (r resumeRequest) bytes() []byte {
	buf := make([]byte, resumeRequestLen)
	copy(buf, r.ID[:])
	binary.BigEndian.PutUint64(buf[resumeIDLen:], r.RecvSeq)
	return buf
}

// encode renders the cookie value: the payload followed by a MAC binding it to
// this handshake.
func (r resumeRequest) encode(psk, nonce []byte, ts int64, binding []byte) string {
	payload := r.bytes()
	mac := computeResumeMAC(psk, "client", nonce, ts, binding, payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, mac...))
}

func decodeResumeRequest(v string, psk, nonce []byte, ts int64, binding []byte) (resumeRequest, error) {
	var r resumeRequest
	payload, err := openResumeCookie(v, resumeRequestLen, psk, "client", nonce, ts, binding)
	if err != nil {
		return r, err
	}
	copy(r.ID[:], payload[:resumeIDLen])
	r.RecvSeq = binary.BigEndian.Uint64(payload[resumeIDLen:])
	return r, nil
}

// openResumeCookie decodes a resume cookie value and checks its MAC, returning
// the payload. An optional prefix is prepended to what the MAC covers — the
// reply binds itself to the request it answers that way.
func openResumeCookie(v string, payloadLen int, psk []byte, role string, nonce []byte, ts int64,
	binding []byte, prefix ...[]byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, errors.New("resume cookie is not valid base64")
	}
	if len(raw) != payloadLen+sha256.Size {
		return nil, errors.New("resume cookie has the wrong length")
	}
	payload, mac := raw[:payloadLen], raw[payloadLen:]
	covered := payload
	if len(prefix) > 0 {
		covered = append(append([]byte{}, prefix[0]...), payload...)
	}
	if !hmac.Equal(computeResumeMAC(psk, role, nonce, ts, binding, covered), mac) {
		return nil, errors.New("resume cookie MAC mismatch")
	}
	return payload, nil
}

// resumeStatus is the server's verdict on a resume request.
type resumeStatus byte

const (
	// resumeNew: no such session existed, one was created. The client starts
	// a fresh multiplexed session over it.
	resumeNew resumeStatus = 1
	// resumeResumed: the session was found and this connection was attached
	// to it. Both sides replay from the exchanged counters.
	resumeResumed resumeStatus = 2
	// resumeGone: the session is no longer available (it expired, or asked to
	// replay from a position that is no longer retained). Everything above the
	// transport has to be rebuilt.
	resumeGone resumeStatus = 3
)

// resumeReply is the server's answer, carrying how many of the client's
// stream bytes it has received so the client knows where to replay from.
type resumeReply struct {
	Status  resumeStatus
	RecvSeq uint64
}

const resumeReplyLen = 1 + 8

func (r resumeReply) bytes() []byte {
	buf := make([]byte, resumeReplyLen)
	buf[0] = byte(r.Status)
	binary.BigEndian.PutUint64(buf[1:], r.RecvSeq)
	return buf
}

// encode renders the answer cookie. Its MAC covers the request as well, so the
// client knows the verdict belongs to the request it actually sent.
func (r resumeReply) encode(psk, nonce []byte, ts int64, binding, requestRaw []byte) string {
	payload := r.bytes()
	mac := computeResumeMAC(psk, "server", nonce, ts, binding,
		append(append([]byte{}, requestRaw...), payload...))
	return base64.RawURLEncoding.EncodeToString(append(payload, mac...))
}

func decodeResumeReply(v string, psk, nonce []byte, ts int64, binding, requestRaw []byte) (resumeReply, error) {
	var r resumeReply
	payload, err := openResumeCookie(v, resumeReplyLen, psk, "server", nonce, ts, binding, requestRaw)
	if err != nil {
		return r, err
	}
	r.Status = resumeStatus(payload[0])
	r.RecvSeq = binary.BigEndian.Uint64(payload[1:])
	return r, nil
}

// resumeRequestFrom pulls the resume request out of an upgrade request. A nil
// request with a nil error means the client did not ask for resumption — an
// older peer, or one with it switched off. An error means the cookie was there
// but not authentic, which is a tampered handshake, not a peer to fall back
// for: honouring it would let anyone on the path force a client to rebuild its
// session by corrupting one cookie.
func resumeRequestFrom(req *http.Request, psk, nonce []byte, ts int64, binding []byte) (*resumeRequest, error) {
	c, err := req.Cookie(resumeCookieName(psk))
	if err != nil {
		return nil, nil
	}
	r, err := decodeResumeRequest(c.Value, psk, nonce, ts, binding)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// resumeReplyFrom pulls the server's answer out of the 101 response cookies. A
// nil answer with a nil error means the server does not implement resumption;
// an error means the answer was tampered with.
func resumeReplyFrom(cookies []*http.Cookie, psk, nonce []byte, ts int64, binding, requestRaw []byte) (*resumeReply, error) {
	name := resumeAckCookieName(psk)
	for _, c := range cookies {
		if c.Name != name {
			continue
		}
		r, err := decodeResumeReply(c.Value, psk, nonce, ts, binding, requestRaw)
		if err != nil {
			return nil, err
		}
		return &r, nil
	}
	return nil, nil
}
