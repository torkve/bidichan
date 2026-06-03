package cli

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProfileHappyPath(t *testing.T) {
	src := `
# Top-level comment, blank line above.
addr           = cdn.example.com:443     # trailing comment
hostname       = cdn.example.com
psk            = aabbccdd
no-tls-binding = true
socket         = /run/foo.sock
`
	v, err := parseProfile(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := derefStr(v.Addr); got != "cdn.example.com:443" {
		t.Errorf("addr = %q", got)
	}
	if got := derefStr(v.Hostname); got != "cdn.example.com" {
		t.Errorf("hostname = %q", got)
	}
	if got := derefStr(v.PSK); got != "aabbccdd" {
		t.Errorf("psk = %q", got)
	}
	if v.NoTLSBinding == nil || *v.NoTLSBinding != true {
		t.Errorf("no-tls-binding = %v", v.NoTLSBinding)
	}
	if got := derefStr(v.Socket); got != "/run/foo.sock" {
		t.Errorf("socket = %q", got)
	}
}

func TestParseProfileEveryKey(t *testing.T) {
	// Two-half fixture: psk and psk-file are mutually exclusive, so we
	// hit each in a separate parse.
	srcInline := `addr           = a:1
unix-socket    = /tmp/u.sock
hostname       = h
psk            = ff
no-tls-binding = false
cert           = /tmp/c.pem
key            = /tmp/k.pem
socket         = /tmp/s.sock`
	v, err := parseProfile(strings.NewReader(srcInline))
	if err != nil {
		t.Fatal(err)
	}
	for k, ptr := range map[string]*string{
		"addr":        v.Addr,
		"unix-socket": v.UnixSocket,
		"hostname":    v.Hostname,
		"psk":         v.PSK,
		"cert":        v.Cert,
		"key":         v.Key,
		"socket":      v.Socket,
	} {
		if ptr == nil {
			t.Errorf("%s not parsed", k)
		}
	}
	if v.NoTLSBinding == nil {
		t.Errorf("no-tls-binding not parsed")
	}

	v2, err := parseProfile(strings.NewReader("psk-file = pf\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v2.PSKFile == nil {
		t.Errorf("psk-file not parsed")
	}
}

func TestParseProfileBoolSpellings(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
		err  bool
	}{
		{"true", true, false}, {"True", true, false}, {"TRUE", true, false},
		{"1", true, false}, {"yes", true, false}, {"on", true, false},
		{"false", false, false}, {"0", false, false},
		{"no", false, false}, {"off", false, false},
		{"sometimes", false, true},
		{"", false, true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			v, err := parseProfile(strings.NewReader("no-tls-binding = " + tc.in))
			if tc.err {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.NoTLSBinding == nil || *v.NoTLSBinding != tc.want {
				t.Fatalf("got %v want %v", v.NoTLSBinding, tc.want)
			}
		})
	}
}

func TestParseProfileCommentsAndCRLF(t *testing.T) {
	// CRLF line endings; full-line and trailing comments.
	src := "# header\r\n\r\naddr = a:1 # inline\r\nhostname = h\r\n"
	v, err := parseProfile(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if derefStr(v.Addr) != "a:1" {
		t.Errorf("addr = %q", derefStr(v.Addr))
	}
	if derefStr(v.Hostname) != "h" {
		t.Errorf("hostname = %q", derefStr(v.Hostname))
	}
}

func TestParseProfileUnknownKey(t *testing.T) {
	_, err := parseProfile(strings.NewReader("addr = a\nthingy = 1\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "thingy") {
		t.Fatalf("error %q does not mention the bad key", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error %q does not mention the line", err)
	}
}

func TestParseProfileMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"missing-eq", "addr foo:1"},
		{"empty-key", "  = foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseProfile(strings.NewReader(tc.in)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseProfilePSKAndPSKFileConflict(t *testing.T) {
	src := "psk = aa\npsk-file = /tmp/x\n"
	if _, err := parseProfile(strings.NewReader(src)); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

func TestExpandPathTilde(t *testing.T) {
	h, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no $HOME")
	}
	if got := expandPath("~/foo/bar"); got != filepath.Join(h, "foo/bar") {
		t.Errorf("got %q want %q", got, filepath.Join(h, "foo/bar"))
	}
	if got := expandPath("~"); got != h {
		t.Errorf("got %q want %q", got, h)
	}
}

func TestExpandPathEnv(t *testing.T) {
	t.Setenv("BIDICHAN_TEST_DIR", "/etc/example")
	if got := expandPath("$BIDICHAN_TEST_DIR/foo"); got != "/etc/example/foo" {
		t.Errorf("got %q", got)
	}
}

func TestResolveProfilePathSearchOrder(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	bdir := filepath.Join(xdg, "bidichan")
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(bdir, "primary.conf")
	if err := os.WriteFile(want, []byte("addr = x:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveProfilePath("primary")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestResolveProfilePathNotFound(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if _, err := resolveProfilePath("nosuch"); err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveProfilePathLiteral(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.conf")
	if err := os.WriteFile(f, []byte("addr = x:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveProfilePath(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != f {
		t.Errorf("got %q want %q", got, f)
	}
}

func TestLoadProfileResolvesRelativePSKFile(t *testing.T) {
	dir := t.TempDir()
	pskPath := filepath.Join(dir, "secret.psk")
	confPath := filepath.Join(dir, "p.conf")
	if err := os.WriteFile(pskPath, []byte("aabbccdd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := "addr = a:1\nhostname = h\npsk-file = secret.psk\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	v, _, err := loadProfile(confPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.PSKFile == nil || *v.PSKFile != pskPath {
		t.Errorf("psk-file = %v, want %s", v.PSKFile, pskPath)
	}
}

func TestLoadProfileWarnsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "p.conf")
	if err := os.WriteFile(conf, []byte("addr = a:1\npsk = aa\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	if _, _, err := loadProfile(conf, logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "world-readable") {
		t.Errorf("expected world-readable warning, got: %q", buf.String())
	}
}

func TestReadPSKFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.psk")
	os.WriteFile(good, []byte("# label\n  aabbccdd  \n"), 0o600)
	got, err := readPSKFile(good)
	if err != nil {
		t.Fatal(err)
	}
	if got != "aabbccdd" {
		t.Errorf("got %q", got)
	}

	empty := filepath.Join(dir, "empty.psk")
	os.WriteFile(empty, []byte("# only a comment\n\n"), 0o600)
	if _, err := readPSKFile(empty); err == nil {
		t.Fatal("expected error for empty psk-file")
	}
}

// derefStr is a tiny helper so tests don't have to nil-check inline.
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// silence "imported and not used" if all logger-using tests get
// commented out.
var _ = io.Discard
