package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/torkve/bidichan/internal/daemon"
)

// Run is the main entry point invoked from main(). It dispatches the
// subcommand and returns a process exit code.
func Run(args []string) int {
	if len(args) < 1 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "listen":
		return runListen(args[1:])
	case "connect":
		return runConnect(args[1:])
	case "status":
		return runStatus(args[1:])
	case "channel":
		return runChannel(args[1:])
	case "shutdown":
		return runShutdown(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `bidichan — DPI-resistant bidirectional transport (TLS 1.2 + SNI)

Commands:
  listen   --addr HOST:PORT --hostname NAME --psk HEX [--cert FILE --key FILE] [--socket PATH]
           listen --unix-socket PATH --hostname NAME --psk HEX [--socket PATH]
           listen [<profile>] [--config NAME-OR-PATH] [flag overrides...]
              Run as the server end. Accepts authenticated peers; serves an
              nginx decoy to everyone else (in TLS mode). With --unix-socket
              the daemon binds a unix socket and skips TLS, expecting a
              reverse proxy (e.g. nginx) to terminate TLS in front.

  connect  --addr HOST:PORT --hostname NAME --psk HEX [--socket PATH]
              [--no-tls-binding]
           connect --unix-socket PATH --hostname NAME --psk HEX
           connect [<profile>] [--config NAME-OR-PATH] [flag overrides...]
              Run as the dialing end. Establishes one peer to the server.
              Pass --no-tls-binding when the server is behind a
              TLS-terminating reverse proxy (binding cannot be shared).

  Config files (listen and connect): a profile name resolves to
  $XDG_CONFIG_HOME/bidichan/<name>.conf, then /etc/bidichan/<name>.conf.
  The file is key=value text ('#' starts a comment) with the same key
  names as the CLI flags (without --). CLI flags override file values.
  Use --psk-file PATH to keep the secret in a separate file.

  status   [--socket PATH]
              Show running peers and open channels on the local daemon.

  channel  open  forward  [--peer ID] [--listen-side local|remote]
                          [-L LADDR:RHOST:RPORT | -R LADDR:RHOST:RPORT]
                          [--listen-addr H:P --target H:P]
           open  http     [--peer ID] [--listen-side local|remote] --listen H:P
           open  socks5   [--peer ID] [--listen-side local|remote] --listen H:P
           open  tun      [--peer ID] [--tun-side local|remote] [--name N]
                          [--cidr 10.42.0.1/24] [--mtu 1400]
           close          [--peer ID] --id CHANNEL_ID

  shutdown [--socket PATH]
              Ask the local daemon to exit.

Auth: --psk is a hex-encoded pre-shared key. Both sides must use the same value.
SNI:  --hostname is sent as TLS SNI and Host: header; server enforces equality.
      Wrong SNI / wrong PSK / wrong path -> nginx default HTML and disconnect.
`)
}

// --- listen ---

func runListen(args []string) int {
	positional, args := peelProfileArg(args)
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	configSrc := fs.String("config", "", "profile name or path to a config file (key=value); CLI flags override the file")
	addr := fs.String("addr", ":443", "TCP listen address (host:port). Ignored if --unix-socket is set.")
	unixPath := fs.String("unix-socket", "", "listen on a unix socket and skip TLS — for behind-nginx deployments")
	hostname := fs.String("hostname", "", "SNI hostname to require (and Host: header in plain mode)")
	pskHex := fs.String("psk", "", "pre-shared key (hex)")
	pskFile := fs.String("psk-file", "", "file containing the hex PSK on a single line")
	certPath := fs.String("cert", "", "TLS certificate PEM (optional; self-signed if absent). Ignored in unix-socket mode.")
	keyPath := fs.String("key", "", "TLS key PEM (optional). Ignored in unix-socket mode.")
	sock := fs.String("socket", "", "local CLI control socket path (default XDG_RUNTIME_DIR/bidichan-<pid>.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := log.New(os.Stderr, "bidichan ", log.LstdFlags|log.Lmicroseconds)

	source, err := profileSourceFrom(positional, *configSrc, "listen")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if path, err := applyProfile(fs, source, logger); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	} else if path != "" {
		logger.Printf("loaded profile %s", path)
	}

	if *pskHex == "" && *pskFile != "" {
		hexStr, err := readPSKFile(*pskFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read --psk-file: %v\n", err)
			return 1
		}
		*pskHex = hexStr
	}
	if *hostname == "" || *pskHex == "" {
		fmt.Fprintln(os.Stderr, "listen: --hostname and --psk (or --psk-file / config) are required")
		return 2
	}
	psk, err := hex.DecodeString(*pskHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad PSK: %v\n", err)
		return 2
	}

	bindAddr := *addr
	network := "tcp"
	if *unixPath != "" {
		bindAddr = *unixPath
		network = "unix"
	}

	d, err := daemon.New(daemon.Config{
		Mode:             daemon.ModeListen,
		BindAddr:         bindAddr,
		Hostname:         *hostname,
		PSK:              psk,
		CertPath:         *certPath,
		KeyPath:          *keyPath,
		TransportNetwork: network,
		ControlSocket:    *sock,
		Logger:           logger,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return runDaemon(d, logger)
}

// --- connect ---

func runConnect(args []string) int {
	positional, args := peelProfileArg(args)
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	configSrc := fs.String("config", "", "profile name or path to a config file (key=value); CLI flags override the file")
	addr := fs.String("addr", "", "remote address (host:port). Ignored if --unix-socket is set.")
	unixPath := fs.String("unix-socket", "", "dial a local unix socket and skip TLS — for behind-nginx testing")
	hostname := fs.String("hostname", "", "SNI hostname to send and require")
	pskHex := fs.String("psk", "", "pre-shared key (hex)")
	pskFile := fs.String("psk-file", "", "file containing the hex PSK on a single line")
	noBind := fs.Bool("no-tls-binding", false, "omit the TLS-unique channel binding from auth — required when the server is behind a TLS-terminating reverse proxy")
	sock := fs.String("socket", "", "local CLI control socket path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := log.New(os.Stderr, "bidichan ", log.LstdFlags|log.Lmicroseconds)

	source, err := profileSourceFrom(positional, *configSrc, "connect")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if path, err := applyProfile(fs, source, logger); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	} else if path != "" {
		logger.Printf("loaded profile %s", path)
	}

	if *pskHex == "" && *pskFile != "" {
		hexStr, err := readPSKFile(*pskFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read --psk-file: %v\n", err)
			return 1
		}
		*pskHex = hexStr
	}
	if *hostname == "" || *pskHex == "" {
		fmt.Fprintln(os.Stderr, "connect: --hostname and --psk (or --psk-file / config) are required")
		return 2
	}
	remote := *addr
	network := "tcp"
	if *unixPath != "" {
		remote = *unixPath
		network = "unix"
	}
	if remote == "" {
		fmt.Fprintln(os.Stderr, "connect: --addr or --unix-socket is required")
		return 2
	}
	psk, err := hex.DecodeString(*pskHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad PSK: %v\n", err)
		return 2
	}

	d, err := daemon.New(daemon.Config{
		Mode:             daemon.ModeConnect,
		RemoteAddr:       remote,
		Hostname:         *hostname,
		PSK:              psk,
		TransportNetwork: network,
		SkipBinding:      *noBind,
		ControlSocket:    *sock,
		Logger:           logger,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return runDaemon(d, logger)
}

func runDaemon(d *daemon.Daemon, logger *log.Logger) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Printf("signal received, shutting down")
		_ = d.Close()
		cancel()
	}()
	if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("daemon: %v", err)
		return 1
	}
	return 0
}

// --- status ---

func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	sock := fs.String("socket", "", "daemon control socket path (auto-discovered if empty)")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := DialCtrl(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	data, err := c.Call(daemon.ActionStatus, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *jsonOut {
		os.Stdout.Write(data)
		os.Stdout.Write([]byte("\n"))
		return 0
	}
	var resp daemon.StatusResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tMODE\tREMOTE\tLOCAL\tUP")
	for _, p := range resp.Peers {
		uptime := time.Since(p.StartedAt).Truncate(time.Second)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Mode, p.Remote, p.Local, uptime)
	}
	tw.Flush()
	for _, p := range resp.Peers {
		if len(p.Channels) == 0 {
			continue
		}
		fmt.Printf("\nChannels on peer %s:\n", p.ID)
		ctw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(ctw, "  ID\tKIND\tROLE\tDESCRIPTION")
		for _, ch := range p.Channels {
			role := "accepted"
			if ch.Originator {
				role = "originated"
			}
			fmt.Fprintf(ctw, "  %d\t%s\t%s\t%s\n", ch.ID, ch.Kind, role, ch.Description)
		}
		ctw.Flush()
	}
	return 0
}

// --- channel ---

func runChannel(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "channel: missing subcommand (open|close)")
		return 2
	}
	switch args[0] {
	case "open":
		return runChannelOpen(args[1:])
	case "close":
		return runChannelClose(args[1:])
	}
	fmt.Fprintf(os.Stderr, "channel: unknown subcommand %q\n", args[0])
	return 2
}

func runChannelOpen(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "channel open: missing kind (forward|http|socks5|tun)")
		return 2
	}
	switch args[0] {
	case "forward":
		return runOpenForward(args[1:])
	case "http":
		return runOpenProxy(args[1:], daemon.ActionOpenHTTP)
	case "socks5":
		return runOpenProxy(args[1:], daemon.ActionOpenSocks5)
	case "tun":
		return runOpenTUN(args[1:])
	}
	fmt.Fprintf(os.Stderr, "channel open: unknown kind %q\n", args[0])
	return 2
}

func runOpenForward(args []string) int {
	fs := flag.NewFlagSet("channel open forward", flag.ExitOnError)
	sock := fs.String("socket", "", "daemon socket")
	peerID := fs.String("peer", "", "peer id (prefix ok)")
	side := fs.String("listen-side", "", "local|remote — which side hosts the listener")
	listenAddr := fs.String("listen-addr", "", "listener address host:port")
	targetAddr := fs.String("target", "", "target address host:port")
	label := fs.String("label", "", "human label")
	short := fs.String("L", "", "SSH-style direct forward LADDR:RHOST:RPORT (listener on local)")
	shortR := fs.String("R", "", "SSH-style reverse forward LADDR:RHOST:RPORT (listener on remote)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *short != "" || *shortR != "" {
		val := *short
		ls := "local"
		if *shortR != "" {
			val = *shortR
			ls = "remote"
		}
		la, ta, err := parseSSHForward(val)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		*listenAddr = la
		*targetAddr = ta
		*side = ls
	}

	if *side == "" || *listenAddr == "" || *targetAddr == "" {
		fmt.Fprintln(os.Stderr, "need --listen-side, --listen-addr, --target (or use -L/-R)")
		return 2
	}

	c, err := DialCtrl(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	data, err := c.Call(daemon.ActionOpenForward, daemon.OpenForwardArgs{
		PeerID:     *peerID,
		ListenSide: *side,
		ListenAddr: *listenAddr,
		TargetAddr: *targetAddr,
		Label:      *label,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var resp daemon.OpenResponse
	_ = json.Unmarshal(data, &resp)
	fmt.Printf("opened forward channel id=%d\n", resp.ChannelID)
	return 0
}

func runOpenProxy(args []string, action string) int {
	fs := flag.NewFlagSet("channel open proxy", flag.ExitOnError)
	sock := fs.String("socket", "", "daemon socket")
	peerID := fs.String("peer", "", "peer id (prefix ok)")
	side := fs.String("listen-side", "local", "local|remote — which side hosts the proxy listener")
	listenAddr := fs.String("listen", "", "listener address host:port")
	label := fs.String("label", "", "human label")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *listenAddr == "" {
		fmt.Fprintln(os.Stderr, "need --listen")
		return 2
	}
	c, err := DialCtrl(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	data, err := c.Call(action, daemon.OpenProxyArgs{
		PeerID:     *peerID,
		ListenSide: *side,
		ListenAddr: *listenAddr,
		Label:      *label,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var resp daemon.OpenResponse
	_ = json.Unmarshal(data, &resp)
	fmt.Printf("opened %s channel id=%d\n", strings.TrimPrefix(action, "open_"), resp.ChannelID)
	return 0
}

func runOpenTUN(args []string) int {
	fs := flag.NewFlagSet("channel open tun", flag.ExitOnError)
	sock := fs.String("socket", "", "daemon socket")
	peerID := fs.String("peer", "", "peer id (prefix ok)")
	side := fs.String("tun-side", "local", "local|remote — which side names the device")
	name := fs.String("name", "", "device name (Linux only)")
	cidr := fs.String("cidr", "", "IP/CIDR to assign (Linux only)")
	mtu := fs.Int("mtu", 1400, "MTU")
	label := fs.String("label", "", "human label")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := DialCtrl(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	data, err := c.Call(daemon.ActionOpenTUN, daemon.OpenTUNArgs{
		PeerID:  *peerID,
		TUNSide: *side,
		Name:    *name,
		CIDR:    *cidr,
		MTU:     *mtu,
		Label:   *label,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var resp daemon.OpenResponse
	_ = json.Unmarshal(data, &resp)
	fmt.Printf("opened tun channel id=%d\n", resp.ChannelID)
	return 0
}

func runChannelClose(args []string) int {
	fs := flag.NewFlagSet("channel close", flag.ExitOnError)
	sock := fs.String("socket", "", "daemon socket")
	peerID := fs.String("peer", "", "peer id (prefix ok)")
	chID := fs.Uint64("id", 0, "channel id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *chID == 0 {
		fmt.Fprintln(os.Stderr, "need --id")
		return 2
	}
	c, err := DialCtrl(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	if _, err := c.Call(daemon.ActionClose, daemon.CloseArgs{PeerID: *peerID, ChannelID: *chID}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("closed channel %d\n", *chID)
	return 0
}

func runShutdown(args []string) int {
	fs := flag.NewFlagSet("shutdown", flag.ExitOnError)
	sock := fs.String("socket", "", "daemon socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := DialCtrl(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer c.Close()
	if _, err := c.Call(daemon.ActionShutdown, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("shutdown requested")
	return 0
}

// parseSSHForward parses "LADDR:RHOST:RPORT" into (listenAddr, targetAddr).
// LADDR may be "8080" (binds 127.0.0.1:8080), ":8080" (all interfaces), or
// "host:8080".
func parseSSHForward(s string) (listen, target string, err error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 3:
		// LPORT:RHOST:RPORT  -> 127.0.0.1:LPORT  RHOST:RPORT
		return "127.0.0.1:" + parts[0], parts[1] + ":" + parts[2], nil
	case 4:
		// LHOST:LPORT:RHOST:RPORT
		return parts[0] + ":" + parts[1], parts[2] + ":" + parts[3], nil
	}
	return "", "", fmt.Errorf("invalid forward spec %q", s)
}
