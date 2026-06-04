package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// findCmd walks the tree rooted at root and returns the subcommand with
// the matching dotted path, e.g. "channel.open.forward".
func findCmd(t *testing.T, root *cobra.Command, dotted string) *cobra.Command {
	t.Helper()
	cur := root
	for _, name := range strings.Split(dotted, ".") {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == name {
				next = c
				break
			}
		}
		if next == nil {
			t.Fatalf("subcommand %q under %q not found", name, cur.CommandPath())
		}
		cur = next
	}
	return cur
}

func TestCommandTreeShape(t *testing.T) {
	root := newRootCmd()

	wantPaths := []string{
		"listen",
		"connect",
		"status",
		"shutdown",
		"channel",
		"channel.open",
		"channel.open.forward",
		"channel.open.http",
		"channel.open.socks5",
		"channel.open.tun",
		"channel.close",
	}
	for _, p := range wantPaths {
		findCmd(t, root, p) // fatal on miss
	}

	// cobra adds a `completion` subcommand at Execute() time; trigger
	// the same init the binary will, then confirm it's wired up so
	// `bidichan completion bash` keeps working.
	root.InitDefaultCompletionCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "completion" {
			found = true
			break
		}
	}
	if !found {
		t.Error("cobra auto completion subcommand missing")
	}
}

func TestListenAndConnectFlags(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"listen", "connect"} {
		c := findCmd(t, root, name)
		// Every flag both commands share.
		for _, flag := range []string{"addr", "unix-socket", "hostname", "psk", "psk-file", "socket", "config"} {
			if c.Flags().Lookup(flag) == nil {
				t.Errorf("%s missing --%s", name, flag)
			}
		}
		if c.ValidArgsFunction == nil {
			t.Errorf("%s: ValidArgsFunction not set (profile completion would not work)", name)
		}
	}
	// listen-only.
	for _, flag := range []string{"cert", "key"} {
		if findCmd(t, root, "listen").Flags().Lookup(flag) == nil {
			t.Errorf("listen missing --%s", flag)
		}
	}
	// connect-only.
	if findCmd(t, root, "connect").Flags().Lookup("no-tls-binding") == nil {
		t.Errorf("connect missing --no-tls-binding")
	}
}

func TestChannelOpenFlags(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"forward", "http", "socks5", "tun"} {
		c := findCmd(t, root, "channel.open."+name)
		if c.Flags().Lookup("socket") == nil {
			t.Errorf("channel open %s missing --socket", name)
		}
		if c.Flags().Lookup("peer") == nil {
			t.Errorf("channel open %s missing --peer", name)
		}
	}
	// forward-only short flags.
	fwd := findCmd(t, root, "channel.open.forward")
	if fwd.Flags().ShorthandLookup("L") == nil || fwd.Flags().ShorthandLookup("R") == nil {
		t.Errorf("forward missing -L / -R shorthands")
	}
	// tun-only flags.
	tun := findCmd(t, root, "channel.open.tun")
	for _, flag := range []string{"tun-side", "name", "cidr", "mtu"} {
		if tun.Flags().Lookup(flag) == nil {
			t.Errorf("tun missing --%s", flag)
		}
	}
}

func TestHelpMentionsKeyFlags(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"listen", "connect"} {
		c := findCmd(t, root, name)
		var buf bytes.Buffer
		c.SetOut(&buf)
		if err := c.Help(); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		for _, flag := range []string{"--addr", "--hostname", "--psk", "--config"} {
			if !strings.Contains(out, flag) {
				t.Errorf("%s --help missing %s; got:\n%s", name, flag, out)
			}
		}
	}
}
