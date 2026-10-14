package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/peer"
)

// A kind the server denies is refused when the client opens it, yet the
// server can still originate that kind on the client.
func TestDeniedKindRefusedButOriginatable(t *testing.T) {
	cli, srv, teardown := pairDenying(t, "example.test", peer.KindForward)
	defer teardown()

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	spec := peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	}
	_, err := cli.OpenChannel(ctx, peer.KindForward, spec)
	if err == nil || !strings.Contains(err.Error(), "--deny-channel forward") {
		t.Fatalf("client open of a denied kind: err = %v, want a deny-channel refusal", err)
	}

	if _, err := srv.OpenChannel(ctx, peer.KindForward, spec); err != nil {
		t.Fatalf("server originating the kind it denies: %v", err)
	}

	// Other kinds stay open to the client.
	if _, err := cli.OpenChannel(ctx, peer.KindSocks5, peer.ProxySpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
	}); err != nil {
		t.Fatalf("client open of an allowed kind: %v", err)
	}
}
