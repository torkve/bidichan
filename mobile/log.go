//go:build ios || android

package mobile

import (
	"io"
	"log"
)

// Logger is implemented on the Swift side to receive diagnostic log lines from
// the embedded bidichan core (transport dial/handshake, peer lifecycle, channel
// events). Each call carries one already-formatted line (it may end with a
// newline). Install it with Client.SetLogger before Start.
//
// Log runs under the standard logger's lock on arbitrary daemon goroutines, so
// it must return promptly and must not re-enter the client (or block on a call
// that logs), or it will stall every other log caller.
type Logger interface {
	Log(line string)
}

// logWriter adapts a Logger to io.Writer so it can back a *log.Logger. The log
// package emits one formatted record per Write, so each Write is one Log call.
type logWriter struct{ l Logger }

func (w logWriter) Write(p []byte) (int, error) {
	if w.l != nil {
		w.l.Log(string(p))
	}
	return len(p), nil
}

// newStdLogger builds the *log.Logger handed to the daemon. A nil Logger
// discards output (the prior behavior).
func newStdLogger(l Logger) *log.Logger {
	if l == nil {
		return log.New(io.Discard, "", 0)
	}
	return log.New(logWriter{l}, "", log.LstdFlags|log.Lmicroseconds)
}
