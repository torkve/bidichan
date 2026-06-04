// Package cli builds bidichan's command tree atop github.com/spf13/cobra.
// Public surface:
//
//	func Execute(args []string) int   // called by main(); returns the
//	                                  // process exit code.
//
// Every subcommand's RunE is a thin wrapper around either a long-lived
// daemon (listen/connect) or a one-shot control-socket request
// (status, channel ..., shutdown). The hand-written usage/completion
// scaffolding the previous incarnation carried is replaced by cobra's
// built-in help and shell-completion generation.
package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/torkve/bidichan/internal/daemon"
)

// Execute parses args and runs the chosen subcommand. Returns the
// process exit code. main() should `os.Exit(cli.Execute(os.Args[1:]))`.
func Execute(args []string) int {
	root := newRootCmd()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		// cobra already printed the error and usage when appropriate.
		// Distinguish "the command failed" (1) from "the user typed
		// it wrong" (2) is hard to do generically with cobra, since
		// SilenceUsage suppresses both. Settle on 1; pflag errors
		// for unknown flags come through the same RunE path with a
		// recognisable wrap, but the cost of mislabelling them as a
		// runtime error vs a usage error is small.
		return 1
	}
	return 0
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "bidichan",
		Short: "DPI-resistant bidirectional transport (TLS 1.2 + SNI)",
		Long: `bidichan establishes a long-lived peer link wrapped in TLS 1.2 with SNI,
authenticated by a pre-shared key.  After authentication both peers are
equal: either side can open or close channels (port-forwarding, HTTP/
SOCKS5 proxies, TUN devices) on the other end.

Wrong SNI / wrong PSK / wrong path → nginx default HTML and disconnect.

Both --psk and --hostname are required on listen and connect; supply them
inline, via --psk-file PATH, or via a peer config profile (see the
"Config files (profiles)" section in the README).`,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(
		newListenCmd(),
		newConnectCmd(),
		newStatusCmd(),
		newChannelCmd(),
		newShutdownCmd(),
	)
	return root
}

// --- listen ---

func newListenCmd() *cobra.Command {
	var (
		configSrc string
		addr      string
		unixPath  string
		hostname  string
		pskHex    string
		pskFile   string
		certPath  string
		keyPath   string
		sock      string
	)
	cmd := &cobra.Command{
		Use:   "listen [<profile>]",
		Short: "Run as the server end",
		Long: `Run as the server end.

Accepts authenticated peers; serves an nginx decoy to everyone else
(in TLS mode). With --unix-socket the daemon binds a unix socket and
skips TLS, expecting a reverse proxy (e.g. nginx) to terminate TLS
in front. An optional positional profile name (or --config name|path)
loads connection settings from $XDG_CONFIG_HOME/bidichan/<name>.conf
or /etc/bidichan/<name>.conf.`,
		Args: cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return ListProfileNames(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			positional := ""
			if len(args) > 0 {
				positional = args[0]
			}
			logger := log.New(os.Stderr, "bidichan ", log.LstdFlags|log.Lmicroseconds)

			source, err := profileSourceFrom(positional, configSrc, "listen")
			if err != nil {
				return err
			}
			if path, err := applyProfile(cmd.Flags(), source, logger); err != nil {
				return err
			} else if path != "" {
				logger.Printf("loaded profile %s", path)
			}

			if pskHex == "" && pskFile != "" {
				h, err := readPSKFile(pskFile)
				if err != nil {
					return fmt.Errorf("read --psk-file: %w", err)
				}
				pskHex = h
			}
			if hostname == "" || pskHex == "" {
				return errors.New("listen: --hostname and --psk (or --psk-file / config) are required")
			}
			psk, err := hex.DecodeString(pskHex)
			if err != nil {
				return fmt.Errorf("bad PSK: %w", err)
			}

			bindAddr := addr
			network := "tcp"
			if unixPath != "" {
				bindAddr = unixPath
				network = "unix"
			}

			d, err := daemon.New(daemon.Config{
				Mode:             daemon.ModeListen,
				BindAddr:         bindAddr,
				Hostname:         hostname,
				PSK:              psk,
				CertPath:         certPath,
				KeyPath:          keyPath,
				TransportNetwork: network,
				ControlSocket:    sock,
				Logger:           logger,
			})
			if err != nil {
				return err
			}
			return runDaemon(cmd.Context(), d, logger)
		},
	}
	f := cmd.Flags()
	f.StringVar(&configSrc, "config", "", "profile name or path to a config file; CLI flags override the file")
	f.StringVar(&addr, "addr", ":443", "TCP listen address (host:port); ignored if --unix-socket is set")
	f.StringVar(&unixPath, "unix-socket", "", "listen on a unix socket and skip TLS — for behind-nginx deployments")
	f.StringVar(&hostname, "hostname", "", "SNI hostname to require (and Host: header in plain mode)")
	f.StringVar(&pskHex, "psk", "", "pre-shared key (hex)")
	f.StringVar(&pskFile, "psk-file", "", "file containing the hex PSK on a single line")
	f.StringVar(&certPath, "cert", "", "TLS certificate PEM (self-signed if absent); ignored in unix-socket mode")
	f.StringVar(&keyPath, "key", "", "TLS key PEM; ignored in unix-socket mode")
	f.StringVar(&sock, "socket", "", "local CLI control socket path (default $XDG_RUNTIME_DIR/bidichan-<pid>.sock)")

	_ = cmd.RegisterFlagCompletionFunc("config", profileFlagCompletion)
	return cmd
}

// --- connect ---

func newConnectCmd() *cobra.Command {
	var (
		configSrc string
		addr      string
		unixPath  string
		hostname  string
		pskHex    string
		pskFile   string
		noBind    bool
		sock      string
	)
	cmd := &cobra.Command{
		Use:   "connect [<profile>]",
		Short: "Run as the dialing end",
		Long: `Run as the dialing end. Establishes one peer to the server.

Pass --no-tls-binding when the server is behind a TLS-terminating
reverse proxy (binding cannot be shared). An optional positional
profile name (or --config name|path) loads connection settings from
$XDG_CONFIG_HOME/bidichan/<name>.conf or /etc/bidichan/<name>.conf.`,
		Args: cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return ListProfileNames(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			positional := ""
			if len(args) > 0 {
				positional = args[0]
			}
			logger := log.New(os.Stderr, "bidichan ", log.LstdFlags|log.Lmicroseconds)

			source, err := profileSourceFrom(positional, configSrc, "connect")
			if err != nil {
				return err
			}
			if path, err := applyProfile(cmd.Flags(), source, logger); err != nil {
				return err
			} else if path != "" {
				logger.Printf("loaded profile %s", path)
			}

			if pskHex == "" && pskFile != "" {
				h, err := readPSKFile(pskFile)
				if err != nil {
					return fmt.Errorf("read --psk-file: %w", err)
				}
				pskHex = h
			}
			if hostname == "" || pskHex == "" {
				return errors.New("connect: --hostname and --psk (or --psk-file / config) are required")
			}
			remote := addr
			network := "tcp"
			if unixPath != "" {
				remote = unixPath
				network = "unix"
			}
			if remote == "" {
				return errors.New("connect: --addr or --unix-socket is required")
			}
			psk, err := hex.DecodeString(pskHex)
			if err != nil {
				return fmt.Errorf("bad PSK: %w", err)
			}

			d, err := daemon.New(daemon.Config{
				Mode:             daemon.ModeConnect,
				RemoteAddr:       remote,
				Hostname:         hostname,
				PSK:              psk,
				TransportNetwork: network,
				SkipBinding:      noBind,
				ControlSocket:    sock,
				Logger:           logger,
			})
			if err != nil {
				return err
			}
			return runDaemon(cmd.Context(), d, logger)
		},
	}
	f := cmd.Flags()
	f.StringVar(&configSrc, "config", "", "profile name or path to a config file; CLI flags override the file")
	f.StringVar(&addr, "addr", "", "remote address (host:port); ignored if --unix-socket is set")
	f.StringVar(&unixPath, "unix-socket", "", "dial a local unix socket and skip TLS — for behind-nginx testing")
	f.StringVar(&hostname, "hostname", "", "SNI hostname to send and require")
	f.StringVar(&pskHex, "psk", "", "pre-shared key (hex)")
	f.StringVar(&pskFile, "psk-file", "", "file containing the hex PSK on a single line")
	f.BoolVar(&noBind, "no-tls-binding", false, "omit the TLS-unique channel binding from auth — required when the server is behind a TLS-terminating reverse proxy")
	f.StringVar(&sock, "socket", "", "local CLI control socket path")

	_ = cmd.RegisterFlagCompletionFunc("config", profileFlagCompletion)
	return cmd
}

// runDaemon runs the long-lived listen/connect daemon, watches for
// SIGINT/SIGTERM, and tears down cleanly. Returns nil on a clean
// shutdown (including signal) so cobra exits 0; surfaces real failures
// as errors.
func runDaemon(parent context.Context, d *daemon.Daemon, logger *log.Logger) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			logger.Printf("signal received, shutting down")
			_ = d.Close()
			cancel()
		case <-ctx.Done():
		}
	}()
	if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// --- status ---

func newStatusCmd() *cobra.Command {
	var (
		sock    string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show running peers and open channels on the local daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := DialCtrl(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			data, err := c.Call(daemon.ActionStatus, nil)
			if err != nil {
				return err
			}
			if jsonOut {
				_, _ = os.Stdout.Write(data)
				_, _ = os.Stdout.Write([]byte("\n"))
				return nil
			}
			var resp daemon.StatusResponse
			if err := json.Unmarshal(data, &resp); err != nil {
				return err
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
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "socket", "", "daemon control socket path (auto-discovered if empty)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

// --- shutdown ---

func newShutdownCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "shutdown",
		Short: "Ask the local daemon to exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := DialCtrl(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			if _, err := c.Call(daemon.ActionShutdown, nil); err != nil {
				return err
			}
			fmt.Println("shutdown requested")
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "socket", "", "daemon control socket path")
	return cmd
}

// --- channel ---

func newChannelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "channel",
		Short: "Open or close a channel on an established peer",
	}
	cmd.AddCommand(newChannelOpenCmd(), newChannelCloseCmd())
	return cmd
}

func newChannelOpenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open",
		Short: "Open a forward / http / socks5 / tun channel",
	}
	cmd.AddCommand(
		newChannelOpenForwardCmd(),
		newChannelOpenProxyCmd("http", daemon.ActionOpenHTTP),
		newChannelOpenProxyCmd("socks5", daemon.ActionOpenSocks5),
		newChannelOpenTUNCmd(),
	)
	return cmd
}

func newChannelOpenForwardCmd() *cobra.Command {
	var (
		sock       string
		peerID     string
		side       string
		listenAddr string
		targetAddr string
		label      string
		short      string
		shortR     string
	)
	cmd := &cobra.Command{
		Use:   "forward",
		Short: "Direct (-L) or reverse (-R) TCP port forwarding",
		Long: `Open a TCP forwarding channel.

The two short forms mirror SSH:
  -L LADDR:RHOST:RPORT   listen on the local side, dial through peer
  -R LADDR:RHOST:RPORT   listen on the peer side, dial through local
The long form takes --listen-side {local|remote}, --listen-addr, and
--target as separate values.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if short != "" || shortR != "" {
				val := short
				ls := "local"
				if shortR != "" {
					val = shortR
					ls = "remote"
				}
				la, ta, err := parseSSHForward(val)
				if err != nil {
					return err
				}
				listenAddr = la
				targetAddr = ta
				side = ls
			}
			if side == "" || listenAddr == "" || targetAddr == "" {
				return errors.New("need --listen-side, --listen-addr, --target (or use -L/-R)")
			}
			c, err := DialCtrl(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			data, err := c.Call(daemon.ActionOpenForward, daemon.OpenForwardArgs{
				PeerID:     peerID,
				ListenSide: side,
				ListenAddr: listenAddr,
				TargetAddr: targetAddr,
				Label:      label,
			})
			if err != nil {
				return err
			}
			var resp daemon.OpenResponse
			_ = json.Unmarshal(data, &resp)
			fmt.Printf("opened forward channel id=%d\n", resp.ChannelID)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&sock, "socket", "", "daemon socket")
	f.StringVar(&peerID, "peer", "", "peer id (prefix ok)")
	f.StringVar(&side, "listen-side", "", "local|remote — which side hosts the listener")
	f.StringVar(&listenAddr, "listen-addr", "", "listener address host:port")
	f.StringVar(&targetAddr, "target", "", "target address host:port")
	f.StringVar(&label, "label", "", "human label")
	f.StringVarP(&short, "L", "L", "", "SSH-style direct forward LADDR:RHOST:RPORT (listener on local)")
	f.StringVarP(&shortR, "R", "R", "", "SSH-style reverse forward LADDR:RHOST:RPORT (listener on remote)")
	_ = cmd.RegisterFlagCompletionFunc("listen-side", localRemoteCompletion)
	return cmd
}

func newChannelOpenProxyCmd(kind, action string) *cobra.Command {
	var (
		sock       string
		peerID     string
		side       string
		listenAddr string
		label      string
	)
	cmd := &cobra.Command{
		Use:   kind,
		Short: "Run an " + kind + " proxy frontend on the chosen side",
		RunE: func(cmd *cobra.Command, args []string) error {
			if listenAddr == "" {
				return errors.New("need --listen")
			}
			c, err := DialCtrl(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			data, err := c.Call(action, daemon.OpenProxyArgs{
				PeerID:     peerID,
				ListenSide: side,
				ListenAddr: listenAddr,
				Label:      label,
			})
			if err != nil {
				return err
			}
			var resp daemon.OpenResponse
			_ = json.Unmarshal(data, &resp)
			fmt.Printf("opened %s channel id=%d\n", kind, resp.ChannelID)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&sock, "socket", "", "daemon socket")
	f.StringVar(&peerID, "peer", "", "peer id (prefix ok)")
	f.StringVar(&side, "listen-side", "local", "local|remote — which side hosts the proxy listener")
	f.StringVar(&listenAddr, "listen", "", "listener address host:port")
	f.StringVar(&label, "label", "", "human label")
	_ = cmd.RegisterFlagCompletionFunc("listen-side", localRemoteCompletion)
	return cmd
}

func newChannelOpenTUNCmd() *cobra.Command {
	var (
		sock   string
		peerID string
		side   string
		name   string
		cidr   string
		mtu    int
		label  string
	)
	cmd := &cobra.Command{
		Use:   "tun",
		Short: "Create a TUN device on the chosen side",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := DialCtrl(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			data, err := c.Call(daemon.ActionOpenTUN, daemon.OpenTUNArgs{
				PeerID:  peerID,
				TUNSide: side,
				Name:    name,
				CIDR:    cidr,
				MTU:     mtu,
				Label:   label,
			})
			if err != nil {
				return err
			}
			var resp daemon.OpenResponse
			_ = json.Unmarshal(data, &resp)
			fmt.Printf("opened tun channel id=%d\n", resp.ChannelID)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&sock, "socket", "", "daemon socket")
	f.StringVar(&peerID, "peer", "", "peer id (prefix ok)")
	f.StringVar(&side, "tun-side", "local", "local|remote — which side names the device")
	f.StringVar(&name, "name", "", "device name (Linux only)")
	f.StringVar(&cidr, "cidr", "", "IP/CIDR to assign (Linux only)")
	f.IntVar(&mtu, "mtu", 1400, "MTU")
	f.StringVar(&label, "label", "", "human label")
	_ = cmd.RegisterFlagCompletionFunc("tun-side", localRemoteCompletion)
	return cmd
}

func newChannelCloseCmd() *cobra.Command {
	var (
		sock   string
		peerID string
		chID   uint64
	)
	cmd := &cobra.Command{
		Use:   "close",
		Short: "Close a channel by id",
		RunE: func(cmd *cobra.Command, args []string) error {
			if chID == 0 {
				return errors.New("need --id")
			}
			c, err := DialCtrl(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			if _, err := c.Call(daemon.ActionClose, daemon.CloseArgs{PeerID: peerID, ChannelID: chID}); err != nil {
				return err
			}
			fmt.Printf("closed channel %d\n", chID)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&sock, "socket", "", "daemon socket")
	f.StringVar(&peerID, "peer", "", "peer id (prefix ok)")
	f.Uint64Var(&chID, "id", 0, "channel id")
	return cmd
}

// --- shared completion helpers ---

// profileFlagCompletion is wired to the --config flag on listen and
// connect; it returns the same profile name list ValidArgsFunction
// returns for the positional, plus file completion (since --config
// also accepts a literal path).
func profileFlagCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	names := ListProfileNames()
	// cobra mixes ShellCompDirectiveDefault (file completion) into
	// suggestions automatically for string flags; returning the
	// profile names alongside that gives the operator both.
	return names, cobra.ShellCompDirectiveDefault
}

func localRemoteCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{"local", "remote"}, cobra.ShellCompDirectiveNoFileComp
}

// parseSSHForward parses "LADDR:RHOST:RPORT" (3 tokens) or
// "LHOST:LPORT:RHOST:RPORT" (4 tokens) into (listenAddr, targetAddr).
func parseSSHForward(s string) (listen, target string, err error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 3:
		return "127.0.0.1:" + parts[0], parts[1] + ":" + parts[2], nil
	case 4:
		return parts[0] + ":" + parts[1], parts[2] + ":" + parts[3], nil
	}
	return "", "", fmt.Errorf("invalid forward spec %q", s)
}

// silence "imported and not used" in case future refactors drop one of
// these standard libs.
var (
	_ = io.Discard
	_ = strconv.Itoa
)
