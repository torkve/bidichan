package cli

import (
	"strings"
	"testing"
)

// requiredFlags lists every long flag (without leading dashes) that
// must appear in every emitted completion script. The intent is to
// guard against somebody adding a flag in commands.go and forgetting
// to mirror it in the completion scripts.
var requiredFlags = []string{
	"config", "addr", "unix-socket", "hostname",
	"psk", "psk-file", "cert", "key", "socket",
	"no-tls-binding",
	"peer", "listen-side", "listen", "target",
	"label",
	"tun-side", "name", "cidr", "mtu",
	"id", "json",
}

// requiredTokens lists subcommands and other plain strings every
// script must mention.
var requiredTokens = []string{
	"listen", "connect", "status", "channel", "shutdown", "completion",
	"open", "close", "forward", "http", "socks5", "tun",
	"bash", "zsh", "fish",
}

// requiredShortFlags lists short flags that must appear. Their syntax
// differs per shell (bash/zsh use `-L`, fish uses `-s L`), so the
// matcher accepts either form.
var requiredShortFlags = []string{"L", "R"}

func hasFlag(shell, script, name string) bool {
	if shell == "fish" {
		return strings.Contains(script, "-l "+name)
	}
	return strings.Contains(script, "--"+name)
}

func hasShortFlag(shell, script, ch string) bool {
	if shell == "fish" {
		return strings.Contains(script, "-s "+ch)
	}
	return strings.Contains(script, "-"+ch)
}

func TestCompletionScriptsCoverAllFlags(t *testing.T) {
	for _, tc := range []struct {
		shell, script string
	}{
		{"bash", bashCompletionScript},
		{"zsh", zshCompletionScript},
		{"fish", fishCompletionScript},
	} {
		t.Run(tc.shell, func(t *testing.T) {
			if len(tc.script) < 200 {
				t.Fatalf("script too short (%d bytes)", len(tc.script))
			}
			for _, tok := range requiredTokens {
				if !strings.Contains(tc.script, tok) {
					t.Errorf("token %q missing from %s script", tok, tc.shell)
				}
			}
			for _, flagName := range requiredFlags {
				if !hasFlag(tc.shell, tc.script, flagName) {
					t.Errorf("flag --%s missing from %s script", flagName, tc.shell)
				}
			}
			for _, ch := range requiredShortFlags {
				if !hasShortFlag(tc.shell, tc.script, ch) {
					t.Errorf("short flag -%s missing from %s script", ch, tc.shell)
				}
			}
		})
	}
}

func TestCompletionScriptsMentionProfileSearchDirs(t *testing.T) {
	// Every shell's discovery path must look in both
	// $XDG_CONFIG_HOME-derived (~/.config/bidichan) and /etc/bidichan.
	// Otherwise profile completion would silently miss either side.
	for _, tc := range []struct {
		shell, script string
	}{
		{"bash", bashCompletionScript},
		{"zsh", zshCompletionScript},
		{"fish", fishCompletionScript},
	} {
		t.Run(tc.shell, func(t *testing.T) {
			for _, want := range []string{"XDG_CONFIG_HOME", "/etc/bidichan"} {
				if !strings.Contains(tc.script, want) {
					t.Errorf("%s script lacks %q in its profile discovery", tc.shell, want)
				}
			}
		})
	}
}

func TestRunCompletionDispatch(t *testing.T) {
	if runCompletion([]string{"unknown"}) == 0 {
		t.Error("unknown shell should fail")
	}
	if runCompletion(nil) == 0 {
		t.Error("missing shell arg should fail")
	}
}
