package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/cli"
	"github.com/torkve/bidichan/internal/daemon"
)

// TestCLIRoundTrip starts a listener daemon and a connecting daemon in-process,
// then drives them via the CLI control socket to open and verify a forward.
func TestCLIRoundTrip(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	psk := mustPSK(t)
	tmp := t.TempDir()
	srvSock := filepath.Join(tmp, "srv.sock")
	cliSock := filepath.Join(tmp, "cli.sock")

	// Pick a free port for the transport.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bindAddr := probe.Addr().String()
	probe.Close()

	srv, err := daemon.New(daemon.Config{
		Mode:          daemon.ModeListen,
		BindAddr:      bindAddr,
		Hostname:      "example.test",
		PSK:           psk,
		ControlSocket: srvSock,
		Logger:        logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctxSrv, cancelSrv := context.WithCancel(context.Background())
	go srv.Run(ctxSrv)
	t.Cleanup(func() {
		cancelSrv()
		_ = srv.Close()
	})

	waitSocket(t, srvSock)

	dialer, err := daemon.New(daemon.Config{
		Mode:          daemon.ModeConnect,
		RemoteAddr:    bindAddr,
		Hostname:      "example.test",
		PSK:           psk,
		ControlSocket: cliSock,
		Logger:        logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctxCli, cancelCli := context.WithCancel(context.Background())
	go dialer.Run(ctxCli)
	t.Cleanup(func() {
		cancelCli()
		_ = dialer.Close()
	})

	waitSocket(t, cliSock)
	// Allow the peer to register on both sides.
	waitForPeer(t, srvSock)
	waitForPeer(t, cliSock)

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	// Open a direct forward via the dialer's CLI socket: listen locally,
	// target the echo on the server side.
	cc, err := cli.DialCtrl(cliSock)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	data, err := cc.Call(daemon.ActionOpenForward, daemon.OpenForwardArgs{
		ListenSide: "local",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoAddr,
	})
	if err != nil {
		t.Fatalf("open forward: %v", err)
	}
	var openResp daemon.OpenResponse
	_ = json.Unmarshal(data, &openResp)
	if openResp.ChannelID == 0 {
		t.Fatal("no channel id returned")
	}

	// Look up the bound listener address via status.
	var listenAddr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		statusData, err := cc.Call(daemon.ActionStatus, nil)
		if err != nil {
			t.Fatal(err)
		}
		var status daemon.StatusResponse
		_ = json.Unmarshal(statusData, &status)
		for _, p := range status.Peers {
			for _, ch := range p.Channels {
				listenAddr = extractListenAddr(ch.Description)
				if listenAddr != "" {
					break
				}
			}
			if listenAddr != "" {
				break
			}
		}
		if listenAddr != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if listenAddr == "" {
		t.Fatal("no listen addr discovered")
	}

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("hello-cli-roundtrip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}

	// Close the channel and verify the listener stops accepting.
	if _, err := cc.Call(daemon.ActionClose, daemon.CloseArgs{ChannelID: openResp.ChannelID}); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Allow propagation; subsequent dial should fail with connection refused
	// (listener has closed).
	time.Sleep(200 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", listenAddr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("expected dial to fail after channel close")
	}
}

func waitSocket(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear", p)
}

func waitForPeer(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cc, err := cli.DialCtrl(sock)
		if err != nil {
			time.Sleep(30 * time.Millisecond)
			continue
		}
		data, err := cc.Call(daemon.ActionStatus, nil)
		cc.Close()
		if err == nil {
			var st daemon.StatusResponse
			_ = json.Unmarshal(data, &st)
			if len(st.Peers) > 0 {
				return
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("daemon %s never registered a peer", sock)
}
