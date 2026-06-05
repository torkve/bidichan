package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// RFC 6455 opcodes.
const (
	wsOpContinuation = 0x0
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// wsMaxFrame caps an inbound frame's payload so a malformed length can't force
// a huge allocation. yamux frames are far smaller than this.
const wsMaxFrame = 8 << 20

// wsConn wraps a net.Conn so the byte stream is carried inside RFC 6455
// WebSocket binary frames. Per the spec the client masks its frames and the
// server does not. We apply this to the *data phase* (after the WebSocket
// handshake), so the connection is standards-compliant WebSocket end to end:
// the post-handshake bytes are valid RFC 6455 frames carrying the multiplexed
// stream.
type wsConn struct {
	inner  net.Conn
	client bool

	wmu sync.Mutex // serialises all frame writes (data, control, cover traffic)

	rmu     sync.Mutex // guards readBuf / Read
	readBuf []byte     // leftover unmasked payload from a partially-consumed frame

	closeOnce sync.Once
	done      chan struct{}
}

// newWSConn wraps inner. client selects RFC 6455 client semantics (mask
// outbound frames). If cover is true, a low-rate randomised stream of ping
// frames is sent as lightweight keepalive traffic.
func newWSConn(inner net.Conn, client, cover bool) *wsConn {
	w := &wsConn{inner: inner, client: client, done: make(chan struct{})}
	if cover {
		go w.coverLoop()
	}
	return w
}

func (w *wsConn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	if len(w.readBuf) > 0 {
		n := copy(p, w.readBuf)
		w.readBuf = w.readBuf[n:]
		return n, nil
	}
	for {
		opcode, payload, err := w.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case wsOpBinary, wsOpContinuation:
			if len(payload) == 0 {
				continue
			}
			n := copy(p, payload)
			if n < len(payload) {
				w.readBuf = payload[n:]
			}
			return n, nil
		case wsOpPing:
			if err := w.writeFrame(wsOpPong, payload); err != nil {
				return 0, err
			}
		case wsOpPong:
			// liveness only; ignore
		case wsOpClose:
			_ = w.writeFrame(wsOpClose, nil)
			return 0, io.EOF
		default:
			return 0, errors.New("ws: unexpected opcode")
		}
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// readFrame reads and unmasks a single frame. Fragmentation is transparent: we
// treat the stream as bytes, so each data frame's payload is returned as-is and
// yamux reassembles its own framing.
func (w *wsConn) readFrame() (opcode byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(w.inner, h[:]); err != nil {
		return 0, nil, err
	}
	opcode = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	n := int(h[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(w.inner, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(w.inner, ext[:]); err != nil {
			return 0, nil, err
		}
		u := binary.BigEndian.Uint64(ext[:])
		if u > wsMaxFrame {
			return 0, nil, errors.New("ws: frame too large")
		}
		n = int(u)
	}
	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(w.inner, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, n)
	if n > 0 {
		if _, err = io.ReadFull(w.inner, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := 0; i < n; i++ {
				payload[i] ^= maskKey[i&3]
			}
		}
	}
	return opcode, payload, nil
}

// writeFrame emits one whole frame (FIN set) in a single Write so the header
// and payload are not split into separate segments.
func (w *wsConn) writeFrame(opcode byte, payload []byte) error {
	n := len(payload)
	headerLen := 2
	switch {
	case n > 0xFFFF:
		headerLen = 10
	case n > 125:
		headerLen = 4
	}
	maskLen := 0
	if w.client {
		maskLen = 4
	}
	frame := make([]byte, headerLen+maskLen+n)
	frame[0] = 0x80 | opcode // FIN + opcode
	switch {
	case n <= 125:
		frame[1] = byte(n)
	case n <= 0xFFFF:
		frame[1] = 126
		binary.BigEndian.PutUint16(frame[2:4], uint16(n))
	default:
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(n))
	}
	off := headerLen
	if w.client {
		frame[1] |= 0x80 // MASK
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(frame[off:off+4], key[:])
		off += 4
		for i := 0; i < n; i++ {
			frame[off+i] = payload[i] ^ key[i&3]
		}
	} else {
		copy(frame[off:], payload)
	}

	w.wmu.Lock()
	defer w.wmu.Unlock()
	_, err := w.inner.Write(frame)
	return err
}

// coverLoop sends a small ping frame at randomised intervals to keep an idle
// connection from going completely silent. Ping frames are standard WebSocket
// control frames; the peer answers with a pong and yamux never sees them.
func (w *wsConn) coverLoop() {
	for {
		t := time.NewTimer(randDuration(15*time.Second, 45*time.Second))
		select {
		case <-w.done:
			t.Stop()
			return
		case <-t.C:
			payload := make([]byte, randIntn(64))
			_, _ = rand.Read(payload)
			if err := w.writeFrame(wsOpPing, payload); err != nil {
				return
			}
		}
	}
}

func (w *wsConn) Close() error {
	w.closeOnce.Do(func() { close(w.done) })
	_ = w.writeFrame(wsOpClose, nil) // best effort
	return w.inner.Close()
}

func (w *wsConn) LocalAddr() net.Addr                { return w.inner.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.inner.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error      { return w.inner.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.inner.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.inner.SetWriteDeadline(t) }

// randDuration returns a uniformly random duration in [min, max].
func randDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(randInt63n(int64(max-min)))
}

func randIntn(n int) int { return int(randInt63n(int64(n))) }

// randInt63n returns a non-negative random int64 in [0, n) using crypto/rand.
func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[:])>>1) % n
}
