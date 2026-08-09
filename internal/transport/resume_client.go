package transport

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

// Reconnect pacing for the redial supervisor.
const (
	reconnectMinDelay = 500 * time.Millisecond
	reconnectMaxDelay = 15 * time.Second
	reconnectTimeout  = 25 * time.Second
)

// LinkState describes what the redial supervisor is doing, for a host that
// wants to show it (the iOS tunnel turns "down" into the system's
// "reasserting" state rather than tearing the tunnel down).
type LinkState int

const (
	// LinkUp: a connection is attached and traffic is flowing.
	LinkUp LinkState = iota
	// LinkDown: the connection was lost; channels are stalled, not closed,
	// and the supervisor is redialing.
	LinkDown
	// LinkFailed: the session could not be resumed within its grace period.
	// Everything above the transport has to be rebuilt.
	LinkFailed
)

func (s LinkState) String() string {
	switch s {
	case LinkUp:
		return "up"
	case LinkDown:
		return "down"
	case LinkFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// DialSession dials addr and returns a connection for the multiplexer that
// survives losing the network: if the link dies it stalls rather than failing,
// redials in the background, and resumes the byte stream exactly where it
// stopped, so the yamux session on top — and every channel and inner TCP
// connection it carries — keeps running.
//
// Against a server that does not implement resumption it transparently falls
// back to the plain connection Dial returns, which dies with the network as
// before. Callers should not assume the result is a *Session.
//
// The supervisor stops when ctx is cancelled or the returned conn is closed.
func DialSession(ctx context.Context, addr string, cfg ClientConfig) (net.Conn, error) {
	logger := cfg.ResumeConfig.Logger
	if logger == nil {
		logger = log.Default()
	}
	id, err := newResumeID()
	if err != nil {
		return nil, fmt.Errorf("resume id: %w", err)
	}
	conn, reply, err := dial(ctx, addr, cfg, &resumeRequest{ID: id})
	if err != nil {
		return nil, err
	}
	if reply == nil {
		logger.Printf("transport: server does not support session resumption; " +
			"the connection will not survive a network change")
		return conn, nil
	}
	if reply.Status != resumeNew {
		_ = conn.Close()
		return nil, fmt.Errorf("transport: unexpected resume status %d on a fresh session", reply.Status)
	}

	rcfg := cfg.ResumeConfig
	rcfg.Logger = logger
	sess := newSession(id, conn, rcfg, nil)
	logger.Printf("transport: session %s established (resumable, grace %s)", id, sess.cfg.Grace)
	cfg.notifyLink(LinkUp, nil)
	go superviseSession(ctx, sess, addr, cfg, logger)
	return sess, nil
}

// notifyLink reports a link transition to the host, if it asked for them.
func (c ClientConfig) notifyLink(state LinkState, err error) {
	if c.OnLinkState != nil {
		c.OnLinkState(state, err)
	}
}

// superviseSession redials whenever the link dies and reattaches the session,
// until the context is cancelled or the session ends for good.
func superviseSession(ctx context.Context, sess *Session, addr string, cfg ClientConfig, logger *log.Logger) {
	defer func() {
		if err := sess.Err(); err != nil {
			cfg.notifyLink(LinkFailed, err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			_ = sess.Close()
			return
		case <-sess.Done():
			return
		case <-sess.LinkLost():
		}
		cfg.notifyLink(LinkDown, nil)
		if !reattach(ctx, sess, addr, cfg, logger) {
			return
		}
		cfg.notifyLink(LinkUp, nil)
	}
}

// reattach redials with backoff until the session is carried again. It reports
// false when the supervisor should stop: the context ended, the session died,
// or the server can no longer resume it.
func reattach(ctx context.Context, sess *Session, addr string, cfg ClientConfig, logger *log.Logger) bool {
	delay := reconnectMinDelay
	for attempt := 1; ; attempt++ {
		select {
		case <-ctx.Done():
			_ = sess.Close()
			return false
		case <-sess.Done():
			return false
		default:
		}

		dialCtx, cancel := context.WithTimeout(ctx, reconnectTimeout)
		conn, reply, err := dial(dialCtx, addr, cfg, &resumeRequest{
			ID:      sess.ID(),
			RecvSeq: sess.RecvSeq(),
		})
		cancel()

		switch {
		case err != nil:
			logger.Printf("transport: session %s reconnect attempt %d failed: %v", sess.ID(), attempt, err)
		case reply == nil:
			// The endpoint answered but no longer speaks resumption — most
			// likely a different server now sits behind the same address.
			_ = conn.Close()
			sess.fail(fmt.Errorf("%w: server stopped offering resumption", ErrResumeUnavailable))
			return false
		case reply.Status == resumeResumed:
			if err := sess.Attach(conn, reply.RecvSeq); err != nil {
				_ = conn.Close()
				return false
			}
			logger.Printf("transport: session %s resumed after %d attempt(s)", sess.ID(), attempt)
			return true
		default:
			// resumeGone (or a fresh session where we expected ours): the
			// server has forgotten us, so the multiplexed state above is
			// worthless and the whole peer has to be rebuilt.
			_ = conn.Close()
			sess.fail(fmt.Errorf("%w: server no longer holds the session", ErrResumeUnavailable))
			return false
		}

		select {
		case <-ctx.Done():
			_ = sess.Close()
			return false
		case <-sess.Done():
			return false
		case <-time.After(jitterDuration(delay)):
		}
		if delay *= 2; delay > reconnectMaxDelay {
			delay = reconnectMaxDelay
		}
	}
}

// DropLink forces a reconnect on a resumable connection. A host that can see
// network changes before a timeout would (iOS reports a new default path when
// the device moves between Wi-Fi and cellular) should call this so the dead
// socket is replaced immediately instead of after the idle timeout.
func DropLink(c net.Conn) {
	if s, ok := c.(*Session); ok {
		s.DropLink()
	}
}
