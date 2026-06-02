package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/peer"
)

// TestChannelMatrix exercises every combination of:
//   - channel kind         ∈ {forward, http, socks5}
//   - originating peer     ∈ {client, server}
//   - listener-side        ∈ {originator, responder}
//
// The test verifies (a) the channel opens, (b) the listener actually binds
// on the expected peer (by inspecting Snapshots), and (c) a payload round-
// trips end-to-end through whatever frontend the channel exposes.
//
// TUN is excluded because it requires CAP_NET_ADMIN and creates real
// network interfaces; it has its own narrower coverage in the manual
// integration story.
func TestChannelMatrix(t *testing.T) {
	type kind string
	const (
		kForward kind = "forward"
		kHTTP    kind = "http"
		kSocks5  kind = "socks5"
	)
	type origin string
	const (
		oClient origin = "client"
		oServer origin = "server"
	)
	type lside string
	const (
		lOrig lside = "originator"
		lResp lside = "responder"
	)

	cases := []struct {
		kind kind
		from origin
		side lside
	}{}
	for _, k := range []kind{kForward, kHTTP, kSocks5} {
		for _, o := range []origin{oClient, oServer} {
			for _, s := range []lside{lOrig, lResp} {
				cases = append(cases, struct {
					kind kind
					from origin
					side lside
				}{k, o, s})
			}
		}
	}

	for _, tc := range cases {
		name := fmt.Sprintf("%s/%s/%s", tc.kind, tc.from, tc.side)
		t.Run(name, func(t *testing.T) {
			cli, srv, teardown := pair(t, "example.test")
			defer teardown()

			echoAddr, stopEcho := startEcho(t)
			defer stopEcho()

			originator := cli
			responder := srv
			if tc.from == oServer {
				originator = srv
				responder = cli
			}
			var listenSide peer.Side
			switch tc.side {
			case lOrig:
				listenSide = peer.SideOriginator
			case lResp:
				listenSide = peer.SideResponder
			}

			// Whichever peer ends up hosting the listener is where we'll
			// snapshot to discover the bound address.
			hostingPeer := originator
			if tc.side == lResp {
				hostingPeer = responder
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var (
				chKind peer.ChannelKind
				spec   any
			)
			switch tc.kind {
			case kForward:
				chKind = peer.KindForward
				spec = peer.ForwardSpec{
					ListenSide: listenSide,
					ListenAddr: "127.0.0.1:0",
					TargetAddr: echoAddr,
				}
			case kHTTP:
				chKind = peer.KindHTTPProxy
				spec = peer.ProxySpec{
					ListenSide: listenSide,
					ListenAddr: "127.0.0.1:0",
				}
			case kSocks5:
				chKind = peer.KindSocks5
				spec = peer.ProxySpec{
					ListenSide: listenSide,
					ListenAddr: "127.0.0.1:0",
				}
			}

			if _, err := originator.OpenChannel(ctx, chKind, spec); err != nil {
				t.Fatalf("OpenChannel: %v", err)
			}

			listenAddr := waitForListener(t, hostingPeer, chKind)
			if listenAddr == "" {
				// Surface what both sides see so the failure is debuggable.
				t.Fatalf("listener address never appeared in %s snapshot; orig=%v resp=%v",
					tc.from, originator.Snapshot(), responder.Snapshot())
			}

			switch tc.kind {
			case kForward:
				assertEchoRoundTrip(t, listenAddr, []byte("hello-forward"))
			case kHTTP:
				assertHTTPProxyRoundTrip(t, listenAddr, echoAddr, []byte("hello-http"))
			case kSocks5:
				assertSocks5RoundTrip(t, listenAddr, echoAddr, []byte("hello-socks5"))
			}
		})
	}
}

// waitForListener polls a peer's Snapshot looking for a channel of the
// given kind whose Description carries a bound listener address.
func waitForListener(t *testing.T, p *peer.Peer, k peer.ChannelKind) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, ch := range p.Snapshot() {
			if ch.Kind != k {
				continue
			}
			if addr := extractListenAddr(ch.Description); addr != "" {
				return addr
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}

func assertEchoRoundTrip(t *testing.T, addr string, payload []byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
}

func assertHTTPProxyRoundTrip(t *testing.T, proxyAddr, target string, payload []byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(c)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		t.Fatalf("CONNECT failed: %q", statusLine)
	}
	// Drain remaining headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}

func assertSocks5RoundTrip(t *testing.T, proxyAddr, target string, payload []byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer c.Close()
	// Greeting (no auth).
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("bad greeting %v", greet)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target: %v", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("expected IPv4 target, got %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("CONNECT rejected: %v", reply)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}
