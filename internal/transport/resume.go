package transport

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// A Session is a reliable, gap-free byte stream carried over an underlying
// transport connection that may be replaced at any time. It exists so a peer's
// yamux session — and therefore every channel and every inner TCP connection
// running over it — survives losing the network: when the link dies the stream
// stalls instead of erroring, and a fresh connection carrying the same session
// ID resumes exactly where the old one stopped.
//
// The wire format inside the link is a 4-byte header (1 type byte + a 24-bit
// big-endian payload length) followed by the payload:
//
//	data 0x01  payload = stream bytes
//	ack  0x02  payload = uint64 big-endian "I have received N stream bytes"
//	ping 0x03  payload = uint64 big-endian recv counter (doubles as an ack)
//	pong 0x04  payload = uint64 big-endian recv counter (doubles as an ack)
//
// Each side counts the stream bytes it has sent and the stream bytes it has
// delivered to its reader, and keeps everything the peer has not acknowledged
// in a bounded send buffer. On resume the two sides exchange their receive
// counters in the HTTP handshake (see resumeRequest / resumeReply) and each
// replays its buffer from the peer's counter, so no byte is lost or duplicated.
//
// A Session is safe for concurrent use. Exactly one goroutine may call Read
// (yamux's receive loop), which matches how net.Conn is used everywhere here.
type Session struct {
	id  ResumeID
	cfg ResumeConfig

	mu   sync.Mutex
	cond *sync.Cond

	// link is the connection currently carrying the session; nil while the
	// network is down. epoch increments on every attach so a goroutine that
	// was blocked on the old link can tell its failure is stale.
	link  net.Conn
	epoch uint64

	sentSeq    uint64 // stream bytes accepted from Write
	ackedSeq   uint64 // stream bytes the peer confirmed receiving
	flushedSeq uint64 // stream bytes written to the current link
	sendBuf    []byte // the bytes in (ackedSeq, sentSeq]

	recvSeq    uint64 // stream bytes delivered by Read
	ackSent    uint64 // recvSeq as of the last ack we put on the wire
	ackPending bool   // recvSeq advanced enough to be worth telling the peer
	// ctrl holds the *types* of queued ping/pong frames, not the frames
	// themselves: each one carries our receive counter, and it has to be the
	// value at the moment it goes out, not at the moment it was queued.
	ctrl []byte

	closed bool
	err    error // permanent failure; Read/Write return it once set

	local, remote net.Addr

	grace *time.Timer

	dead     chan struct{}
	deadOnce sync.Once
	// linkDown carries at most one pending "the link died" notification for
	// the redial supervisor; the server side simply lets the grace timer run.
	linkDown chan struct{}

	onDead func(ResumeID)

	// Reader state. Only Read touches these, but epoch comparison happens
	// under mu.
	readEpoch uint64
	frameLeft int
	hdrBuf    [resumeHeaderLen]byte
}

// ResumeID identifies a session across the connections that carry it.
type ResumeID [resumeIDLen]byte

// String renders the ID as the compact base64 form used in cookies and logs.
func (r ResumeID) String() string { return base64.RawURLEncoding.EncodeToString(r[:]) }

const (
	resumeIDLen     = 16
	resumeHeaderLen = 4

	frameData = 0x01
	frameAck  = 0x02
	framePing = 0x03
	framePong = 0x04

	// resumeChunk caps how many buffered bytes go into one data frame, so a
	// retransmission after a long outage does not allocate the whole buffer.
	resumeChunk = 64 << 10

	// resumeAckThreshold is how many received-but-unacknowledged bytes trigger
	// an ack frame. It bounds how far the peer's send buffer runs ahead of
	// what it may discard.
	resumeAckThreshold = 64 << 10
)

// Defaults for ResumeConfig. The grace period is what actually decides how
// long a flap may last: connections carried by the session stall for up to
// this long and then fail.
const (
	DefaultResumeBuffer    = 4 << 20
	DefaultResumeGrace     = 90 * time.Second
	DefaultResumeKeepalive = 20 * time.Second
	DefaultResumeIdle      = 75 * time.Second
)

// ResumeConfig tunes a Session. The zero value is filled in with the defaults
// above.
type ResumeConfig struct {
	// MaxBuffer caps the unacknowledged send buffer. Writes block once it is
	// full, which propagates backpressure into yamux and on into the channels.
	MaxBuffer int
	// Grace is how long the session tolerates having no link before failing.
	Grace time.Duration
	// Keepalive is the interval between ping frames on an idle link.
	Keepalive time.Duration
	// IdleTimeout declares the link dead when nothing arrives for this long.
	// Must comfortably exceed the peer's keepalive interval.
	IdleTimeout time.Duration
	Logger      *log.Logger
}

func (c ResumeConfig) withDefaults() ResumeConfig {
	if c.MaxBuffer <= 0 {
		c.MaxBuffer = DefaultResumeBuffer
	}
	if c.Grace <= 0 {
		c.Grace = DefaultResumeGrace
	}
	if c.Keepalive <= 0 {
		c.Keepalive = DefaultResumeKeepalive
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultResumeIdle
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	return c
}

// ErrResumeUnavailable is returned when a peer asks to resume from a position
// we can no longer serve (its counter is outside our retained buffer, or the
// session is already gone). The connection has to be rebuilt from scratch.
var ErrResumeUnavailable = errors.New("transport: session cannot be resumed")

// newResumeID returns a fresh random session identifier.
func newResumeID() (ResumeID, error) {
	var id ResumeID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return id, nil
}

// newSession wraps conn as the first link of a new session.
func newSession(id ResumeID, conn net.Conn, cfg ResumeConfig, onDead func(ResumeID)) *Session {
	s := &Session{
		id:       id,
		cfg:      cfg.withDefaults(),
		link:     conn,
		epoch:    1,
		local:    conn.LocalAddr(),
		remote:   conn.RemoteAddr(),
		dead:     make(chan struct{}),
		linkDown: make(chan struct{}, 1),
		onDead:   onDead,
	}
	s.cond = sync.NewCond(&s.mu)
	s.readEpoch = s.epoch
	go s.flushLoop()
	go s.keepaliveLoop()
	return s
}

// ID returns the session identifier carried in the resume handshake.
func (s *Session) ID() ResumeID { return s.id }

// Done is closed once the session has ended, for any reason.
func (s *Session) Done() <-chan struct{} { return s.dead }

// LinkLost delivers a notification every time the underlying connection dies,
// so a supervisor can redial. At most one notification is pending at a time.
func (s *Session) LinkLost() <-chan struct{} { return s.linkDown }

// Attached reports whether a connection is currently carrying the session.
func (s *Session) Attached() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link != nil
}

// ResumeGrace is how long the session tolerates having no link. The peer layer
// reads it to keep yamux's own timers well clear of it.
func (s *Session) ResumeGrace() time.Duration { return s.cfg.Grace }

// RecvSeq is how many stream bytes we have delivered to our reader — the
// position the peer must replay from when it reconnects.
func (s *Session) RecvSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recvSeq
}

// Read implements net.Conn. It blocks while the link is down instead of
// failing, and returns an error only once the session has permanently ended.
func (s *Session) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		for s.link == nil && !s.closed && s.err == nil {
			s.cond.Wait()
		}
		if err := s.stateErrLocked(); err != nil {
			s.mu.Unlock()
			return 0, err
		}
		link, epoch := s.link, s.epoch
		if epoch != s.readEpoch {
			// The link was replaced: any half-read frame died with it and the
			// peer replays from our recvSeq, which is always a delivered-byte
			// boundary.
			s.readEpoch = epoch
			s.frameLeft = 0
		}
		s.mu.Unlock()

		if s.frameLeft == 0 {
			if err := s.readFrameHeader(link, epoch); err != nil {
				if errors.Is(err, errStaleLink) {
					continue
				}
				return 0, err
			}
			continue
		}

		n := len(p)
		if n > s.frameLeft {
			n = s.frameLeft
		}
		read, err := s.linkRead(link, p[:n])
		if read > 0 {
			s.mu.Lock()
			if s.link != link {
				// The connection was detached while this read was in flight,
				// because a resuming one took over. Whatever it produced sits
				// past the position we told the peer to replay from, so it has
				// to be dropped: the peer is sending those bytes again, and
				// counting them here would deliver them twice.
				s.mu.Unlock()
				continue
			}
			s.frameLeft -= read
			s.recvSeq += uint64(read)
			if s.recvSeq-s.ackSent >= resumeAckThreshold {
				s.ackPending = true
				s.cond.Broadcast()
			}
			s.mu.Unlock()
			return read, nil
		}
		if err != nil {
			s.linkFailed(epoch, err)
		}
	}
}

// prepareResume detaches whatever connection is carrying the session and
// reports how far our reader got, in one step. The two have to be atomic: the
// number goes into the handshake as "replay from here", so if the old
// connection were allowed to deliver one more byte afterwards we would end up
// with the peer's replay overlapping what we had already taken.
func (s *Session) prepareResume() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stateErrLocked(); err != nil {
		return 0, err
	}
	s.linkFailedLocked(s.epoch, errResumedElsewhere)
	return s.recvSeq, nil
}

var errResumedElsewhere = errors.New("transport: superseded by a resuming connection")

// errStaleLink means the current link died and the caller should re-loop; it
// never reaches a caller of Read/Write.
var errStaleLink = errors.New("transport: link replaced")

// readFrameHeader reads one frame header and handles every non-data frame
// inline, leaving frameLeft set when a data frame arrives.
func (s *Session) readFrameHeader(link net.Conn, epoch uint64) error {
	if err := s.readFull(link, s.hdrBuf[:]); err != nil {
		s.linkFailed(epoch, err)
		return errStaleLink
	}
	typ := s.hdrBuf[0]
	n := int(s.hdrBuf[1])<<16 | int(s.hdrBuf[2])<<8 | int(s.hdrBuf[3])
	switch typ {
	case frameData:
		s.frameLeft = n
		return nil
	case frameAck, framePing, framePong:
		if n != 8 {
			err := fmt.Errorf("transport: resume frame 0x%02x with %d-byte payload", typ, n)
			s.fail(err)
			return err
		}
		var buf [8]byte
		if err := s.readFull(link, buf[:]); err != nil {
			s.linkFailed(epoch, err)
			return errStaleLink
		}
		s.applyAck(binary.BigEndian.Uint64(buf[:]))
		if typ == framePing {
			s.queueControl(framePong)
		}
		return nil
	default:
		err := fmt.Errorf("transport: unknown resume frame type 0x%02x", typ)
		s.fail(err)
		return err
	}
}

func (s *Session) readFull(link net.Conn, p []byte) error {
	for off := 0; off < len(p); {
		n, err := s.linkRead(link, p[off:])
		off += n
		if err != nil {
			if off == len(p) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (s *Session) linkRead(link net.Conn, p []byte) (int, error) {
	if s.cfg.IdleTimeout > 0 {
		_ = link.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
	}
	return link.Read(p)
}

// Write implements net.Conn. It buffers the bytes and returns as soon as they
// are queued: the flusher puts them on the link, and keeps them until the peer
// acknowledges them so they can be replayed after a reconnect. It blocks only
// when the send buffer is full (backpressure) or the session has ended.
func (s *Session) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if err := s.stateErrLocked(); err != nil {
			return 0, err
		}
		// An oversized single write is admitted when the buffer is empty,
		// otherwise it could never make progress.
		if len(s.sendBuf) == 0 || len(s.sendBuf)+len(p) <= s.cfg.MaxBuffer {
			break
		}
		s.cond.Wait()
	}
	s.sendBuf = append(s.sendBuf, p...)
	s.sentSeq += uint64(len(p))
	s.cond.Broadcast()
	return len(p), nil
}

// applyAck records that the peer has received seq stream bytes and releases
// the buffer up to that point.
func (s *Session) applyAck(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseLocked(seq)
}

func (s *Session) releaseLocked(seq uint64) {
	if seq <= s.ackedSeq || seq > s.sentSeq {
		return
	}
	drop := int(seq - s.ackedSeq)
	if drop > len(s.sendBuf) {
		drop = len(s.sendBuf)
	}
	// Compact in place. The flusher copies the bytes it is about to write
	// while holding mu, so nothing aliases sendBuf here.
	s.sendBuf = append(s.sendBuf[:0], s.sendBuf[drop:]...)
	s.ackedSeq = seq
	if s.flushedSeq < s.ackedSeq {
		s.flushedSeq = s.ackedSeq
	}
	s.cond.Broadcast()
}

// maxQueuedControl bounds the ping/pong backlog, so a peer that pings faster
// than we can write cannot grow the queue without limit. Dropping the excess
// costs nothing: each frame carries the same counter, so one is as good as ten.
const maxQueuedControl = 8

// queueControl asks the flusher to send a ping or pong.
func (s *Session) queueControl(typ byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.err != nil || len(s.ctrl) >= maxQueuedControl {
		return
	}
	s.ctrl = append(s.ctrl, typ)
	s.cond.Broadcast()
}

// buildFrame renders a control frame carrying a single counter.
func buildFrame(typ byte, seq uint64) []byte {
	f := make([]byte, resumeHeaderLen+8)
	f[0] = typ
	f[3] = 8
	binary.BigEndian.PutUint64(f[resumeHeaderLen:], seq)
	return f
}

// flushLoop owns every write to the link: control frames first, then a pending
// ack, then buffered stream bytes from flushedSeq. Because it is the only
// writer, a reattach can simply rewind flushedSeq and the retransmission
// happens in order, ahead of anything written later.
//
// Acknowledgements deliberately take priority over data and are never gated on
// the send buffer having room: a full buffer is released *by* the peer's acks,
// so a peer whose own buffer is full must still be able to tell us what it has
// received, or two saturated directions would deadlock each other.
func (s *Session) flushLoop() {
	for {
		s.mu.Lock()
		for {
			if s.closed || s.err != nil {
				s.mu.Unlock()
				return
			}
			if s.link != nil && (len(s.ctrl) > 0 || s.ackPending || s.flushedSeq < s.sentSeq) {
				break
			}
			s.cond.Wait()
		}
		link, epoch := s.link, s.epoch

		var (
			frame []byte
			// target is where flushedSeq must end up if this write lands —
			// an absolute position, not an increment. While the write is in
			// flight the lock is released, and an ack arriving in that window
			// can pull flushedSeq forward on its own (releaseLocked). Adding
			// to whatever it has become by then would count the same bytes
			// twice and leave a hole in the stream that nothing retransmits.
			target uint64
		)
		switch {
		case len(s.ctrl) > 0:
			// Built here, with the counter as it stands now — a ping or pong
			// doubles as an acknowledgement, so it also settles a pending one.
			typ := s.ctrl[0]
			s.ctrl = s.ctrl[1:]
			frame = buildFrame(typ, s.recvSeq)
			s.ackSent = s.recvSeq
			s.ackPending = false
		case s.ackPending:
			s.ackPending = false
			s.ackSent = s.recvSeq
			frame = buildFrame(frameAck, s.recvSeq)
		default:
			off := int(s.flushedSeq - s.ackedSeq)
			end := len(s.sendBuf)
			if end-off > resumeChunk {
				end = off + resumeChunk
			}
			payload := s.sendBuf[off:end]
			frame = make([]byte, resumeHeaderLen+len(payload))
			frame[0] = frameData
			frame[1] = byte(len(payload) >> 16)
			frame[2] = byte(len(payload) >> 8)
			frame[3] = byte(len(payload))
			copy(frame[resumeHeaderLen:], payload)
			target = s.flushedSeq + uint64(len(payload))
		}
		s.mu.Unlock()

		// A black-holed path would otherwise wedge here until the kernel gives
		// up; the deadline turns it into an ordinary link failure.
		if s.cfg.IdleTimeout > 0 {
			_ = link.SetWriteDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		_, err := link.Write(frame)

		s.mu.Lock()
		switch {
		case err != nil:
			s.linkFailedLocked(epoch, err)
		case s.epoch != epoch:
			// A reattach happened while we were writing; it already rewound
			// flushedSeq to where the peer asked us to replay from.
		case s.flushedSeq < target:
			s.flushedSeq = target
		}
		s.mu.Unlock()
	}
}

// keepaliveLoop pings an idle link so the peer's idle timeout does not fire and
// so a black-holed path is noticed instead of hanging forever.
func (s *Session) keepaliveLoop() {
	for {
		t := time.NewTimer(jitterDuration(s.cfg.Keepalive))
		select {
		case <-s.dead:
			t.Stop()
			return
		case <-t.C:
		}
		s.mu.Lock()
		up := s.link != nil
		s.mu.Unlock()
		if up {
			s.queueControl(framePing)
		}
	}
}

// jitterDuration spreads a timer by ±25% so the keepalive cadence is not a
// fixed beat on the wire.
func jitterDuration(d time.Duration) time.Duration {
	spread := d / 4
	if spread <= 0 {
		return d
	}
	return d - spread + time.Duration(randInt63n(int64(2*spread)))
}

// Attach installs conn as the session's link, replaying everything the peer
// has not seen. peerRecvSeq is how many of our stream bytes the peer reports
// having received.
func (s *Session) Attach(conn net.Conn, peerRecvSeq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stateErrLocked(); err != nil {
		return err
	}
	if peerRecvSeq < s.ackedSeq || peerRecvSeq > s.sentSeq {
		// The peer is asking for bytes we have already discarded, or claims to
		// have more than we ever sent. Neither is recoverable.
		s.failLocked(fmt.Errorf("%w: peer at %d, retained (%d,%d]",
			ErrResumeUnavailable, peerRecvSeq, s.ackedSeq, s.sentSeq))
		return s.err
	}
	s.releaseLocked(peerRecvSeq)
	s.flushedSeq = peerRecvSeq

	if s.link != nil {
		old := s.link
		s.link = nil
		go old.Close()
	}
	s.link = conn
	s.epoch++
	s.local, s.remote = conn.LocalAddr(), conn.RemoteAddr()
	if s.grace != nil {
		s.grace.Stop()
		s.grace = nil
	}
	// Tell the peer where we are as soon as the link is usable, so it can
	// release its own buffer without waiting for traffic.
	s.ackPending = true
	s.cond.Broadcast()
	return nil
}

// DropLink tears down the current connection so the supervisor redials
// immediately. Used when the host tells us the network path changed, which is
// far quicker than waiting for the idle timeout.
func (s *Session) DropLink() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linkFailedLocked(s.epoch, errors.New("transport: link dropped by request"))
}

func (s *Session) linkFailed(epoch uint64, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linkFailedLocked(epoch, cause)
}

func (s *Session) linkFailedLocked(epoch uint64, cause error) {
	if s.closed || s.err != nil || s.link == nil || s.epoch != epoch {
		return
	}
	old := s.link
	s.link = nil
	go old.Close()
	s.cfg.Logger.Printf("transport: session %s link down: %v (buffered %d B, grace %s)",
		s.id, cause, len(s.sendBuf), s.cfg.Grace)
	if s.grace == nil {
		s.grace = time.AfterFunc(s.cfg.Grace, func() {
			s.fail(fmt.Errorf("%w: no reconnect within %s", ErrResumeUnavailable, s.cfg.Grace))
		})
	}
	select {
	case s.linkDown <- struct{}{}:
	default:
	}
	s.cond.Broadcast()
}

// fail ends the session permanently.
func (s *Session) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked(err)
}

func (s *Session) failLocked(err error) {
	if s.closed || s.err != nil {
		return
	}
	s.err = err
	s.teardownLocked()
}

// Close implements net.Conn and ends the session.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.teardownLocked()
	return nil
}

func (s *Session) teardownLocked() {
	if s.grace != nil {
		s.grace.Stop()
		s.grace = nil
	}
	if s.link != nil {
		go s.link.Close()
		s.link = nil
	}
	s.cond.Broadcast()
	s.deadOnce.Do(func() {
		close(s.dead)
		if s.onDead != nil {
			go s.onDead(s.id)
		}
	})
}

func (s *Session) stateErrLocked() error {
	if s.err != nil {
		return s.err
	}
	if s.closed {
		return net.ErrClosed
	}
	return nil
}

// Err returns the permanent failure that ended the session, if any.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.local
}

func (s *Session) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remote
}

// Deadlines are meaningless for a stream that deliberately stalls across a
// reconnect, so they are accepted and ignored. Nothing above this layer sets
// them: yamux never touches the connection's deadlines, and the transport
// clears them before handing the connection over.
func (s *Session) SetDeadline(time.Time) error      { return nil }
func (s *Session) SetReadDeadline(time.Time) error  { return nil }
func (s *Session) SetWriteDeadline(time.Time) error { return nil }

// Resumable marks this connection as one whose stalls are recoverable, so the
// peer layer can relax yamux's own liveness timers (see peer.NewPeer).
func (s *Session) Resumable() bool { return true }

// maxLiveSessions bounds how many resumable sessions one listener will hold.
// Each detached session pins up to MaxBuffer of retransmit data for the whole
// grace period, so an authenticated peer that reconnects in a tight loop must
// not be able to grow that without limit. Reaching the cap does not refuse the
// connection — it is served without resumption, exactly like an older client.
const maxLiveSessions = 128

// sessionRegistry holds the live sessions on the listening side so a
// reconnecting client can be reattached to the one it left behind.
type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[ResumeID]*Session
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{sessions: make(map[ResumeID]*Session)}
}

func (r *sessionRegistry) get(id ResumeID) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[id]
}

// full reports whether the listener is at capacity and should serve further
// clients without resumption.
func (r *sessionRegistry) full() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions) >= maxLiveSessions
}

func (r *sessionRegistry) add(s *Session) {
	r.mu.Lock()
	r.sessions[s.ID()] = s
	r.mu.Unlock()
	// A session that died between construction and registration already ran
	// its removal callback against an empty table, so drop it here instead of
	// leaving the entry behind.
	select {
	case <-s.Done():
		r.remove(s.ID())
	default:
	}
}

func (r *sessionRegistry) remove(id ResumeID) {
	r.mu.Lock()
	delete(r.sessions, id)
	r.mu.Unlock()
}

// closeAll ends every live session; called when the listener shuts down.
func (r *sessionRegistry) closeAll() {
	r.mu.Lock()
	all := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		all = append(all, s)
	}
	r.sessions = make(map[ResumeID]*Session)
	r.mu.Unlock()
	for _, s := range all {
		_ = s.Close()
	}
}
