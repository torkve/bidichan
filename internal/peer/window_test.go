package peer

import (
	"testing"

	"github.com/hashicorp/yamux"
)

// yamux refuses a window below its own initial one, and it refuses it when the
// session is created — which on the listen side is after a peer has already
// authenticated. MinStreamWindow exists so a caller can be told first, so it
// had better be the value yamux actually enforces.
func TestMinStreamWindowIsWhatYamuxAccepts(t *testing.T) {
	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = MinStreamWindow
	if err := yamux.VerifyConfig(cfg); err != nil {
		t.Fatalf("yamux rejects MinStreamWindow (%d): %v", MinStreamWindow, err)
	}
	cfg.MaxStreamWindowSize = MinStreamWindow - 1
	if err := yamux.VerifyConfig(cfg); err == nil {
		t.Fatal("yamux accepts a window below MinStreamWindow; the constant is now wrong")
	}
}

// Asking for less than the protocol allows means "as little as possible", not
// "fail" — the flag is a memory ceiling, and refusing a peer over it would be
// a worse answer than giving the smallest window there is.
func TestTooSmallAWindowIsRaisedNotRefused(t *testing.T) {
	var o peerOptions
	WithMaxStreamWindow(64 << 10)(&o)
	if o.maxStreamWindow != MinStreamWindow {
		t.Fatalf("got %d, want it raised to %d", o.maxStreamWindow, MinStreamWindow)
	}
}

// Zero means "unset", which has to leave the default alone rather than
// configure a window of nothing.
func TestZeroWindowLeavesTheDefault(t *testing.T) {
	o := peerOptions{maxStreamWindow: DefaultStreamWindow}
	WithMaxStreamWindow(0)(&o)
	if o.maxStreamWindow != DefaultStreamWindow {
		t.Fatalf("got %d, want the default %d", o.maxStreamWindow, DefaultStreamWindow)
	}
}
