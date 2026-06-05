package cli

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/torkve/bidichan/internal/daemon"
)

func TestParseAutoChannel(t *testing.T) {
	ok := []struct {
		in   string
		want daemon.AutoChannel
	}{
		{"forward -L 8080:web:80", daemon.AutoChannel{Kind: "forward", Side: "local", ListenAddr: "127.0.0.1:8080", TargetAddr: "web:80"}},
		{"forward -R 2222:localhost:22", daemon.AutoChannel{Kind: "forward", Side: "remote", ListenAddr: "127.0.0.1:2222", TargetAddr: "localhost:22"}},
		{"forward --listen-side remote --listen-addr 0.0.0.0:80 --target h:90 --label web", daemon.AutoChannel{Kind: "forward", Side: "remote", ListenAddr: "0.0.0.0:80", TargetAddr: "h:90", Label: "web"}},
		{"socks5 --listen 127.0.0.1:1080", daemon.AutoChannel{Kind: "socks5", Side: "local", ListenAddr: "127.0.0.1:1080"}},
		{"http --listen 127.0.0.1:8080 --listen-side remote", daemon.AutoChannel{Kind: "http", Side: "remote", ListenAddr: "127.0.0.1:8080"}},
		{"tun --cidr 10.0.0.2/24 --mtu 1400", daemon.AutoChannel{Kind: "tun", Side: "local", CIDR: "10.0.0.2/24", MTU: 1400}},
		{`forward -L 9000:h:9 --label "two words"`, daemon.AutoChannel{Kind: "forward", Side: "local", ListenAddr: "127.0.0.1:9000", TargetAddr: "h:9", Label: "two words"}},
	}
	for _, c := range ok {
		got, err := parseAutoChannel(c.in)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("%q:\n got %+v\nwant %+v", c.in, got, c.want)
		}
	}

	bad := []string{
		"",                       // empty
		"bogus -L x",             // unknown kind
		"forward -L notenough",   // bad -L form
		"forward",                // missing listen/target
		"socks5",                 // missing --listen
		`forward -L 1:2:3 --bad`, // unknown flag
	}
	for _, in := range bad {
		if _, err := parseAutoChannel(in); err == nil {
			t.Errorf("expected error for %q, got nil", in)
		}
	}
}

func TestProfileChannels(t *testing.T) {
	// Repeated `channel =` lines accumulate, in order.
	v, err := parseProfile(strings.NewReader(
		"channel = forward -L 1:h:2\nchannel = socks5 --listen 127.0.0.1:1080\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Channels) != 2 || v.Channels[0] != "forward -L 1:h:2" ||
		v.Channels[1] != "socks5 --listen 127.0.0.1:1080" {
		t.Fatalf("channels = %#v", v.Channels)
	}

	logger := log.New(io.Discard, "", 0)
	dir := t.TempDir()
	prof := filepath.Join(dir, "prof.conf")
	if err := os.WriteFile(prof,
		[]byte("channel = forward -L 1:h:2\nchannel = http --listen 127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// applyProfile fills the repeatable flag from the file.
	fs := pflag.NewFlagSet("connect", pflag.ContinueOnError)
	var ch []string
	fs.StringArrayVar(&ch, "channel", nil, "")
	if _, err := applyProfile(fs, prof, logger); err != nil {
		t.Fatal(err)
	}
	if len(ch) != 2 {
		t.Fatalf("applyProfile channels = %#v", ch)
	}

	// A CLI-set --channel overrides the config list entirely.
	fs2 := pflag.NewFlagSet("connect", pflag.ContinueOnError)
	var ch2 []string
	fs2.StringArrayVar(&ch2, "channel", nil, "")
	_ = fs2.Set("channel", "tun --cidr 10.0.0.2/24")
	if _, err := applyProfile(fs2, prof, logger); err != nil {
		t.Fatal(err)
	}
	if len(ch2) != 1 || ch2[0] != "tun --cidr 10.0.0.2/24" {
		t.Fatalf("override channels = %#v", ch2)
	}
}
