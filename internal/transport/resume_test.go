package transport

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// testResumeConfig keeps the timers short so a test can exercise the whole
// outage path without waiting the production grace period out.
func testResumeConfig() ResumeConfig {
	return ResumeConfig{
		MaxBuffer:   64 << 10,
		Grace:       2 * time.Second,
		Keepalive:   200 * time.Millisecond,
		IdleTimeout: time.Second,
		Logger:      log.New(io.Discard, "", 0),
	}
}

// sessionPair is two sessions wired to each other, with the ability to cut the
// connection between them the way a network outage would and to reconnect them
// the way the handshake does — by telling each side how far the other got.
type sessionPair struct {
	a, b *Session
}

func newSessionPair(t *testing.T, cfg ResumeConfig) *sessionPair {
	t.Helper()
	ca, cb := net.Pipe()
	idA, err := newResumeID()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := newResumeID()
	if err != nil {
		t.Fatal(err)
	}
	p := &sessionPair{
		a: newSession(idA, ca, cfg, nil),
		b: newSession(idB, cb, cfg, nil),
	}
	t.Cleanup(func() {
		_ = p.a.Close()
		_ = p.b.Close()
	})
	return p
}

// cut kills the connection currently carrying both sessions and waits until
// each side has noticed.
func (p *sessionPair) cut(t *testing.T) {
	t.Helper()
	p.a.DropLink()
	p.b.DropLink()
	waitFor(t, 2*time.Second, func() bool { return !p.a.Attached() && !p.b.Attached() })
}

// reconnect attaches a fresh connection, exchanging receive counters exactly as
// the resume handshake does.
func (p *sessionPair) reconnect(t *testing.T) {
	t.Helper()
	ca, cb := net.Pipe()
	aRecv, bRecv := p.a.RecvSeq(), p.b.RecvSeq()
	if err := p.a.Attach(ca, bRecv); err != nil {
		t.Fatalf("attach a: %v", err)
	}
	if err := p.b.Attach(cb, aRecv); err != nil {
		t.Fatalf("attach b: %v", err)
	}
}

// drain consumes everything a session delivers, standing in for the reader
// that always exists above a real session (yamux's receive loop). Without one,
// the peer's acknowledgements have nowhere to go and its writes stall.
func drain(s *Session) {
	go func() { _, _ = io.Copy(io.Discard, s) }()
}

func waitFor(t *testing.T, limit time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", limit)
}

func TestSessionTransfersBothWays(t *testing.T) {
	p := newSessionPair(t, testResumeConfig())

	want := []byte("hello over a resumable link")
	go func() { _, _ = p.a.Write(want) }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(p.b, got); err != nil {
		t.Fatalf("read a->b: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("a->b: got %q want %q", got, want)
	}

	go func() { _, _ = p.b.Write(want) }()
	got = make([]byte, len(want))
	if _, err := io.ReadFull(p.a, got); err != nil {
		t.Fatalf("read b->a: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("b->a: got %q want %q", got, want)
	}
}

// TestSessionSurvivesLinkCuts is the property this whole layer exists for: no
// matter where the connection is severed, the byte stream the reader sees is
// exactly the byte stream the writer produced — no gap, no duplicate, no
// reordering. It cuts repeatedly, at points chosen by the scheduler rather
// than by the test, including mid-frame.
func TestSessionSurvivesLinkCuts(t *testing.T) {
	p := newSessionPair(t, testResumeConfig())
	drain(p.a)

	const chunks = 200
	const chunkSize = 700
	payload := make([]byte, chunks*chunkSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	writeErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		for i := 0; i < chunks; i++ {
			if _, err := p.a.Write(payload[i*chunkSize : (i+1)*chunkSize]); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	got := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(p.b, got)
		readDone <- err
	}()

	// Cut the link underneath the transfer, repeatedly.
	for i := 0; i < 8; i++ {
		time.Sleep(3 * time.Millisecond)
		p.cut(t)
		p.reconnect(t)
	}

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("transfer did not finish")
	}
	wg.Wait()
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("stream diverges at byte %d of %d", i, len(payload))
			}
		}
		t.Fatal("stream differs in length")
	}
}

// A cut that is never repaired must end the session once the grace period is
// spent, and surface that to both Read and Write rather than hanging.
func TestSessionFailsAfterGrace(t *testing.T) {
	cfg := testResumeConfig()
	cfg.Grace = 300 * time.Millisecond
	p := newSessionPair(t, cfg)

	p.cut(t)

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := p.b.Read(buf)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read should fail once the grace period is spent")
		}
		if !errors.Is(err, ErrResumeUnavailable) {
			t.Fatalf("read: got %v, want ErrResumeUnavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not fail after the grace period")
	}
	// The writing side gives up too, on its own timer — the two sides notice
	// the outage a moment apart. Until then a Write only buffers, which is
	// exactly what lets a short flap pass unnoticed.
	waitFor(t, 5*time.Second, func() bool {
		_, err := p.a.Write([]byte("x"))
		return err != nil
	})
}

// Reconnecting after the grace period has already killed the session must be
// refused rather than silently producing a broken stream.
func TestAttachAfterFailureIsRefused(t *testing.T) {
	cfg := testResumeConfig()
	cfg.Grace = 200 * time.Millisecond
	p := newSessionPair(t, cfg)
	p.cut(t)
	waitFor(t, 5*time.Second, func() bool { return p.a.Err() != nil })

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if err := p.a.Attach(c1, 0); err == nil {
		t.Fatal("attaching to a dead session should fail")
	}
}

// A peer that asks to replay from a position we have already released cannot
// be served; the session must fail loudly instead of skipping bytes.
func TestAttachBeyondRetainedBufferFails(t *testing.T) {
	p := newSessionPair(t, testResumeConfig())
	drain(p.a)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.CopyN(io.Discard, p.b, 32)
	}()
	if _, err := p.a.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	<-done
	p.cut(t)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	// 4096 is far beyond anything we ever sent.
	if err := p.a.Attach(c1, 4096); !errors.Is(err, ErrResumeUnavailable) {
		t.Fatalf("attach: got %v, want ErrResumeUnavailable", err)
	}
	_ = c2
}

// Acknowledgements must release the send buffer, or a long-lived session would
// wedge as soon as it had written MaxBuffer bytes.
func TestAcksReleaseSendBuffer(t *testing.T) {
	cfg := testResumeConfig()
	cfg.MaxBuffer = 16 << 10
	p := newSessionPair(t, cfg)
	drain(p.a)

	total := 8 * cfg.MaxBuffer
	go func() {
		buf := make([]byte, 4096)
		for written := 0; written < total; written += len(buf) {
			if _, err := p.a.Write(buf); err != nil {
				return
			}
		}
	}()

	if _, err := io.CopyN(io.Discard, p.b, int64(total)); err != nil {
		t.Fatalf("drain: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool {
		p.a.mu.Lock()
		defer p.a.mu.Unlock()
		return len(p.a.sendBuf) == 0
	})
}

// Close must unblock a reader that is parked waiting for the link to come back.
func TestCloseUnblocksStalledRead(t *testing.T) {
	p := newSessionPair(t, testResumeConfig())
	p.cut(t)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, err := p.b.Read(buf)
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = p.b.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("read after Close should fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the stalled read")
	}
}

// ackingConn acknowledges each data frame from inside Write, i.e. exactly
// while the flusher has released the lock and is waiting on the wire. That is
// the real timing whenever a write blocks on a full socket buffer and the peer
// drains and acknowledges in the meantime.
type ackingConn struct {
	net.Conn
	mu    sync.Mutex
	sess  *Session
	acked uint64
}

func (c *ackingConn) bind(s *Session) {
	c.mu.Lock()
	c.sess = s
	c.mu.Unlock()
}

func (c *ackingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil || len(p) <= resumeHeaderLen || p[0] != frameData {
		return n, err
	}
	c.mu.Lock()
	c.acked += uint64(len(p) - resumeHeaderLen)
	seq, sess := c.acked, c.sess
	c.mu.Unlock()
	if sess != nil {
		sess.applyAck(seq)
	}
	return n, err
}

// The flusher records how far it has written after the write returns, by which
// time an acknowledgement may already have moved that mark forward. Treating
// its own progress as an increment rather than a position made it count the
// same bytes twice, skip a stretch of the stream, and go idle believing
// everything had been sent — a silent hole, not an error.
func TestFlushSurvivesAckArrivingMidWrite(t *testing.T) {
	cfg := testResumeConfig()
	ca, cb := tcpPipe(t)
	hook := &ackingConn{Conn: ca}

	id, err := newResumeID()
	if err != nil {
		t.Fatal(err)
	}
	a := newSession(id, hook, cfg, nil)
	hook.bind(a)
	b := newSession(id, cb, cfg, nil)
	defer a.Close()
	defer b.Close()
	drain(a)

	const size = 512 << 10
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		const chunk = 8192
		for off := 0; off < size; off += chunk {
			if _, err := a.Write(payload[off : off+chunk]); err != nil {
				return
			}
		}
	}()

	got := make([]byte, size)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(b, got)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("stream stalled: the flusher believes it sent bytes it skipped")
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("stream diverges at byte %d of %d", i, size)
			}
		}
		t.Fatal("stream differs in length")
	}
}

// tcpPipe returns a connected pair over loopback. Unlike net.Pipe it buffers,
// which is what makes it possible to have bytes in flight on a connection that
// is about to be replaced.
func tcpPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := lis.Accept()
		ch <- accepted{c, err}
	}()
	client, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-ch
	if server.err != nil {
		t.Fatal(server.err)
	}
	return client, server.conn
}

// A connection can still be alive, and still be carrying bytes, when a
// resuming one arrives — the client redials as soon as the device changes
// network, long before the old socket is known to be dead. The position that
// goes into the handshake and the detaching of the old connection therefore
// have to happen together: if the old one delivered one more byte afterwards,
// the peer's replay would overlap it and the stream would gain duplicates.
func TestResumeWhileOldLinkStillCarriesData(t *testing.T) {
	cfg := testResumeConfig()
	ca, cb := tcpPipe(t)
	idA, err := newResumeID()
	if err != nil {
		t.Fatal(err)
	}
	a := newSession(idA, ca, cfg, nil)
	b := newSession(idA, cb, cfg, nil)
	defer a.Close()
	defer b.Close()
	drain(a)

	const size = 2 << 20
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		const chunk = 4096
		for off := 0; off < size; off += chunk {
			if _, err := a.Write(payload[off : off+chunk]); err != nil {
				return
			}
		}
	}()

	// Read continuously, so the takeovers below land while a read is in flight
	// on the connection being replaced — that is the window the bookkeeping
	// has to be safe across.
	got := make([]byte, size)
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(b, got)
		readDone <- err
	}()

	// Take the session over, repeatedly, without ever declaring the previous
	// connection dead first: this is the listener's half of a resume.
	for i := 0; i < 60; i++ {
		time.Sleep(time.Millisecond)
		bRecv, err := b.prepareResume()
		if err != nil {
			t.Fatalf("prepareResume: %v", err)
		}
		a.DropLink()
		aRecv := a.RecvSeq()

		na, nb := tcpPipe(t)
		if err := a.Attach(na, bRecv); err != nil {
			t.Fatalf("attach a: %v", err)
		}
		if err := b.Attach(nb, aRecv); err != nil {
			t.Fatalf("attach b: %v", err)
		}
	}

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("transfer did not finish")
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("stream diverges at byte %d of %d", i, size)
			}
		}
		t.Fatal("stream differs in length")
	}
}

func TestResumeHandshakeCodecRoundTrip(t *testing.T) {
	psk := []byte("0123456789abcdef")
	nonce := []byte("nonce-nonce-nonc")
	ts := time.Now().Unix()
	binding := []byte("binding")

	id, err := newResumeID()
	if err != nil {
		t.Fatal(err)
	}
	req := resumeRequest{ID: id, RecvSeq: 1 << 40}
	back, err := decodeResumeRequest(req.encode(psk, nonce, ts, binding), psk, nonce, ts, binding)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if back != req {
		t.Fatalf("request round trip: got %+v want %+v", back, req)
	}
	// The MAC is over the canonical bytes, so a decoded request must re-encode
	// to exactly what the peer signed.
	if !bytes.Equal(back.bytes(), req.bytes()) {
		t.Fatal("re-encoded request bytes differ")
	}

	reply := resumeReply{Status: resumeResumed, RecvSeq: 12345}
	encoded := reply.encode(psk, nonce, ts, binding, req.bytes())
	rback, err := decodeResumeReply(encoded, psk, nonce, ts, binding, req.bytes())
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if rback != reply {
		t.Fatalf("reply round trip: got %+v want %+v", rback, reply)
	}
	// The answer is bound to the request it answers, so it cannot be lifted
	// onto a different one.
	other := resumeRequest{ID: id, RecvSeq: 7}
	if _, err := decodeResumeReply(encoded, psk, nonce, ts, binding, other.bytes()); err == nil {
		t.Fatal("an answer to one request was accepted for another")
	}
}

// The resume position rides in a cookie, so it has to carry its own MAC — a
// forged counter would make one side skip bytes the other still needs.
func TestResumeCookieRejectsTampering(t *testing.T) {
	psk := []byte("0123456789abcdef")
	nonce := []byte("nonce-nonce-nonc")
	ts := time.Now().Unix()
	binding := []byte("binding")

	id, err := newResumeID()
	if err != nil {
		t.Fatal(err)
	}
	honest := resumeRequest{ID: id, RecvSeq: 1000}
	cookie := honest.encode(psk, nonce, ts, binding)

	// Rewriting the counter must not survive the MAC.
	forged := resumeRequest{ID: id, RecvSeq: 9999}
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		t.Fatal(err)
	}
	copy(raw, forged.bytes())
	if _, err := decodeResumeRequest(base64.RawURLEncoding.EncodeToString(raw),
		psk, nonce, ts, binding); err == nil {
		t.Fatal("a forged resume position was accepted")
	}

	// Nor may a cookie be replayed onto a different handshake.
	if _, err := decodeResumeRequest(cookie, psk, nonce, ts+1, binding); err == nil {
		t.Fatal("a resume cookie was accepted with a different timestamp")
	}
	if _, err := decodeResumeRequest(cookie, psk, nonce, ts, []byte("other")); err == nil {
		t.Fatal("a resume cookie was accepted with a different channel binding")
	}
}

// Resumption must not disturb the handshake MAC itself: a peer that knows
// nothing about it computes the same value, which is the whole reason old and
// new peers still talk to each other. This pins the legacy inputs.
func TestAuthMACIsUnchangedByResumption(t *testing.T) {
	psk := []byte("0123456789abcdef")
	nonce := []byte("nonce-nonce-nonc")
	ts := int64(1700000000)
	binding := []byte("binding")

	// Golden value, computed from the definition that predates resumption:
	// HMAC-SHA256(psk, role || 0 || nonce || 0 || decimal(ts) || 0 || binding).
	want := hmac.New(sha256.New, psk)
	want.Write([]byte("client"))
	want.Write([]byte{0})
	want.Write(nonce)
	want.Write([]byte{0})
	want.Write([]byte(strconv.FormatInt(ts, 10)))
	want.Write([]byte{0})
	want.Write(binding)

	if got := computeAuthMAC(psk, "client", nonce, ts, binding); !bytes.Equal(got, want.Sum(nil)) {
		t.Fatal("computeAuthMAC no longer matches the pre-resumption definition")
	}

	// And the resume MAC is a different keyed function, so neither can stand in
	// for the other.
	if bytes.Equal(computeAuthMAC(psk, "client", nonce, ts, binding),
		computeResumeMAC(psk, "client", nonce, ts, binding, nil)) {
		t.Fatal("the resume MAC collides with the handshake MAC")
	}
}
