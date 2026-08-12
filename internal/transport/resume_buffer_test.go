package transport

import (
	"io"
	"testing"
	"time"
)

// A session at MinResumeBuffer must be drained by threshold acks, not by the
// counters that ride on the keepalive.
//
// This is the property that makes the floor the floor. Below it a full buffer
// never reaches resumeAckThreshold outstanding bytes, so the receiver never
// volunteers an ack, and the sender only drains when a keepalive happens to
// carry a counter — at the production interval of 20s, a few kilobytes a
// second. The keepalive here is set far longer than the test would tolerate,
// so if anything but threshold acks were releasing the buffer this would time
// out rather than pass.
func TestMinBufferDrainsOnAcksNotKeepalives(t *testing.T) {
	cfg := testResumeConfig()
	cfg.MaxBuffer = MinResumeBuffer
	cfg.Keepalive = 10 * time.Minute
	cfg.IdleTimeout = 20 * time.Minute
	p := newSessionPair(t, cfg)
	// The acks travel back as frames on a's link, and a only takes them off
	// that link while something is reading it. Without this the sender never
	// learns it may discard, and the test deadlocks rather than measuring.
	drain(p.a)

	// Several buffers' worth, so the buffer has to be released repeatedly
	// rather than merely swallowing the payload whole.
	total := 4 * cfg.MaxBuffer
	go func() {
		buf := make([]byte, 4096)
		for written := 0; written < total; written += len(buf) {
			if _, err := p.a.Write(buf); err != nil {
				return
			}
		}
	}()

	// Bounded here rather than by reading inline, so a regression fails saying
	// what went wrong instead of hanging until the package timeout kills it.
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyN(io.Discard, p.b, int64(total))
		done <- err
	}()

	// Completing at all is the result: the buffer holds a quarter of this
	// payload, so three quarters of it could only move if the sender was told
	// repeatedly that it might discard — and with the keepalive ten minutes
	// away, a threshold ack is the only thing that could have told it.
	//
	// Not asserted: that the send buffer ends empty. The last bytes written
	// are fewer than a threshold, so nothing provokes a final ack and they sit
	// there until the next transfer or a keepalive. That is the mechanism
	// working rather than failing, and demanding otherwise would pin a promise
	// the design does not make.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("moving %d bytes stalled — acks are not releasing the buffer", total)
	}
}

// The floor is two ack thresholds, so a full buffer always crosses the point
// at which the receiver volunteers one. Pinned because that relationship is
// the entire reason for the constant, and the two values are written far
// enough apart that neither reads as tied to the other.
func TestMinResumeBufferClearsTheAckThreshold(t *testing.T) {
	if MinResumeBuffer < 2*resumeAckThreshold {
		t.Fatalf("MinResumeBuffer %d is below two ack thresholds (%d)",
			MinResumeBuffer, 2*resumeAckThreshold)
	}
	if DefaultResumeBuffer < MinResumeBuffer {
		t.Fatalf("the default %d is below the minimum %d", DefaultResumeBuffer, MinResumeBuffer)
	}
}
