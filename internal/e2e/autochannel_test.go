package e2e

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/cli"
	"github.com/torkve/bidichan/internal/daemon"
)

// TestConnectAutoChannel verifies that a connect daemon configured with
// AutoChannels opens them automatically once the peer is up — with no
// `channel open` call — and that the resulting forward round-trips bytes.
func TestConnectAutoChannel(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	psk := mustPSK(t)
	tmp := t.TempDir()
	srvSock := filepath.Join(tmp, "srv.sock")
	cliSock := filepath.Join(tmp, "cli.sock")

	certPEM, keyPEM := mustGenCertPEM(t, "example.test")
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	mustWrite(t, certPath, certPEM, 0o644)
	mustWrite(t, keyPath, keyPEM, 0o644)

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
		CertPath:      certPath,
		KeyPath:       keyPath,
		ControlSocket: srvSock,
		Logger:        logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctxSrv, cancelSrv := context.WithCancel(context.Background())
	go srv.Run(ctxSrv)
	t.Cleanup(func() { cancelSrv(); _ = srv.Close() })
	waitSocket(t, srvSock)

	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()

	// Connect daemon with an auto-opened forward (local listen → echo on the
	// peer side). No manual channel open anywhere.
	dialer, err := daemon.New(daemon.Config{
		Mode:          daemon.ModeConnect,
		RemoteAddr:    bindAddr,
		Hostname:      "example.test",
		PSK:           psk,
		CACert:        certPath,
		ControlSocket: cliSock,
		Logger:        logger,
		AutoChannels: []daemon.AutoChannel{
			{Kind: "forward", Side: "local", ListenAddr: "127.0.0.1:0", TargetAddr: echoAddr},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctxCli, cancelCli := context.WithCancel(context.Background())
	go dialer.Run(ctxCli)
	t.Cleanup(func() { cancelCli(); _ = dialer.Close() })
	waitSocket(t, cliSock)
	waitForPeer(t, srvSock)
	waitForPeer(t, cliSock)

	// Poll status until the auto-channel's listener is bound.
	cc, err := cli.DialCtrl(cliSock)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

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
				if a := extractListenAddr(ch.Description); a != "" {
					listenAddr = a
				}
			}
		}
		if listenAddr != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if listenAddr == "" {
		t.Fatal("auto-channel listener never bound")
	}

	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("auto-channel-roundtrip")
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
}
