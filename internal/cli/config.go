package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// profileValues holds the union of fields a `listen` or `connect` config
// file may set. Every field is a pointer so the merger can tell "key was
// in the file" apart from "key defaulted to the zero value".
type profileValues struct {
	Addr         *string
	UnixSocket   *string
	Hostname     *string
	PSK          *string
	PSKFile      *string
	NoTLSBinding *bool
	Cert         *string
	Key          *string
	Socket       *string
}

// loadProfile resolves a profile source — either an explicit path passed
// via `--config`, a profile name passed positionally or via `--config`,
// or nothing — and returns the parsed values plus the absolute path it
// loaded from (for diagnostics). When source is empty it returns nil
// values and an empty path with no error.
//
// Resolution rules for profile names (no slash, no .conf suffix):
//  1. $XDG_CONFIG_HOME/bidichan/<name>.conf (falls back to
//     $HOME/.config/bidichan/<name>.conf when XDG_CONFIG_HOME is unset).
//  2. /etc/bidichan/<name>.conf
//
// Anything else is treated as a literal path.
func loadProfile(source string, logger *log.Logger) (*profileValues, string, error) {
	if source == "" {
		return nil, "", nil
	}
	path, err := resolveProfilePath(source)
	if err != nil {
		return nil, "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	if logger != nil {
		warnLooseSecretPerms(logger, path, f)
	}
	vals, err := parseProfile(f)
	if err != nil {
		return nil, path, fmt.Errorf("parse %s: %w", path, err)
	}
	// Resolve psk-file relative to the config dir; warn on loose perms.
	if vals.PSKFile != nil {
		resolved := expandPath(*vals.PSKFile)
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(filepath.Dir(path), resolved)
		}
		vals.PSKFile = &resolved
		if logger != nil {
			if pf, err := os.Open(resolved); err == nil {
				warnLooseSecretPerms(logger, resolved, pf)
				_ = pf.Close()
			}
		}
	}
	return vals, path, nil
}

// resolveProfilePath maps a profile name or literal path to an absolute
// path on disk. A source containing a path separator, starting with
// `~`, or ending in `.conf` is treated as a literal path.
func resolveProfilePath(source string) (string, error) {
	if looksLikePath(source) {
		expanded := expandPath(source)
		abs, err := filepath.Abs(expanded)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	for _, dir := range profileSearchDirs() {
		candidate := filepath.Join(dir, source+".conf")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no profile %q in any of %v", source, profileSearchDirs())
}

func looksLikePath(s string) bool {
	return strings.ContainsAny(s, "/\\") ||
		strings.HasPrefix(s, "~") ||
		strings.HasSuffix(s, ".conf")
}

func profileSearchDirs() []string {
	var dirs []string
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		dirs = append(dirs, filepath.Join(v, "bidichan"))
	} else if h, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(h, ".config", "bidichan"))
	}
	dirs = append(dirs, "/etc/bidichan")
	return dirs
}

// expandPath replaces a leading `~/` with $HOME and expands $VARS via
// os.ExpandEnv. We intentionally do not expand mid-string `~` since
// that would surprise the operator.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(h, p[2:])
		}
	} else if p == "~" {
		if h, err := os.UserHomeDir(); err == nil {
			p = h
		}
	}
	return os.ExpandEnv(p)
}

// parseProfile reads `key = value` lines from r. Whitespace around
// keys and values is trimmed; `#` introduces a comment that extends to
// end-of-line. Unknown keys are a hard error so typos surface at
// startup. The function never reads any external state — it is pure
// over its io.Reader so it is trivially testable.
func parseProfile(r io.Reader) (*profileValues, error) {
	out := &profileValues{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4<<10), 64<<10)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := stripComment(sc.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: missing '='", lineNo)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", lineNo)
		}
		if err := applyKey(out, key, val); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if out.PSK != nil && out.PSKFile != nil {
		return nil, errors.New("psk and psk-file are mutually exclusive")
	}
	return out, nil
}

// stripComment removes any `#`-introduced comment from a line. It is
// `#`-or-EOL anywhere outside no special context (we do not have
// quoted strings to worry about).
func stripComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i]
	}
	return s
}

func applyKey(out *profileValues, key, val string) error {
	switch strings.ToLower(key) {
	case "addr":
		out.Addr = strPtr(val)
	case "unix-socket":
		out.UnixSocket = strPtr(expandPath(val))
	case "hostname":
		out.Hostname = strPtr(val)
	case "psk":
		out.PSK = strPtr(val)
	case "psk-file":
		// Path expansion happens after the config path is known
		// (loadProfile resolves relative paths against the config dir).
		out.PSKFile = strPtr(val)
	case "no-tls-binding":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("no-tls-binding: %w", err)
		}
		out.NoTLSBinding = &b
	case "cert":
		out.Cert = strPtr(expandPath(val))
	case "key":
		out.Key = strPtr(expandPath(val))
	case "socket":
		out.Socket = strPtr(expandPath(val))
	default:
		return fmt.Errorf("unknown key %q (known keys: addr, unix-socket, hostname, psk, psk-file, no-tls-binding, cert, key, socket)", key)
	}
	return nil
}

func strPtr(s string) *string { return &s }

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q (expected true/false/1/0/yes/no/on/off)", v)
}

// readPSKFile reads a single line of hex from path, trimmed of
// whitespace. Returns the hex string (caller hex-decodes).
func readPSKFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Take only the first non-empty line, trimmed.
	for _, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s != "" && !strings.HasPrefix(s, "#") {
			return s, nil
		}
	}
	return "", errors.New("psk file empty")
}

// warnLooseSecretPerms logs a warning when a file that may contain a
// secret is readable by group or world. Soft check — we never refuse
// to start over it, since some operators legitimately delegate read
// access via a group (the bidichan@.service unit uses group bidichan
// for /etc/bidichan/*.env, mode 0640).
func warnLooseSecretPerms(logger *log.Logger, path string, f *os.File) {
	st, err := f.Stat()
	if err != nil {
		return
	}
	mode := st.Mode().Perm()
	if mode&0o006 != 0 {
		logger.Printf("warning: %s is world-readable (mode %#o); secrets in this file are exposed to every local user", path, mode)
	}
}

// applyProfile resolves and loads a profile (positional or --config) and
// applies it to flags the user did NOT set on the CLI. Returns the file
// path that was loaded (for diagnostics) or empty if no profile source
// was provided.
//
// Profile keys that have no matching flag on the given FlagSet (e.g. a
// `no-tls-binding` key in a `listen` profile) are silently ignored —
// this lets one profile be shared between client and server invocations.
func applyProfile(fs interface {
	Lookup(string) *flag.Flag
	Visit(func(*flag.Flag))
}, source string, logger *log.Logger) (string, error) {
	if source == "" {
		return "", nil
	}
	v, path, err := loadProfile(source, logger)
	if err != nil {
		return path, err
	}
	setOnCLI := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setOnCLI[f.Name] = true })

	set := func(name, val string) {
		if setOnCLI[name] {
			return
		}
		if f := fs.Lookup(name); f != nil {
			_ = f.Value.Set(val)
		}
	}
	if v.Addr != nil {
		set("addr", *v.Addr)
	}
	if v.UnixSocket != nil {
		set("unix-socket", *v.UnixSocket)
	}
	if v.Hostname != nil {
		set("hostname", *v.Hostname)
	}
	if v.PSK != nil {
		set("psk", *v.PSK)
	}
	if v.PSKFile != nil {
		set("psk-file", *v.PSKFile)
	}
	if v.NoTLSBinding != nil {
		if *v.NoTLSBinding {
			set("no-tls-binding", "true")
		} else {
			set("no-tls-binding", "false")
		}
	}
	if v.Cert != nil {
		set("cert", *v.Cert)
	}
	if v.Key != nil {
		set("key", *v.Key)
	}
	if v.Socket != nil {
		set("socket", *v.Socket)
	}
	return path, nil
}

// profileSourceFrom combines an optional positional profile name with
// an optional --config flag value. Returns the single source string to
// hand to applyProfile, or an error if both are set (ambiguous).
func profileSourceFrom(positional, configFlag, cmdName string) (string, error) {
	if positional != "" && configFlag != "" {
		return "", fmt.Errorf("%s: cannot use both positional profile %q and --config %q", cmdName, positional, configFlag)
	}
	if configFlag != "" {
		return configFlag, nil
	}
	return positional, nil
}

// peelProfileArg pulls an optional leading positional profile name out
// of args (anything that does not start with '-' or '/'). Returns the
// detected profile name (or "") and the remaining args to be passed to
// FlagSet.Parse.
//
// Literal paths (containing '/' or starting with '~') are NOT consumed
// here — callers should use --config for explicit paths. This keeps
// the positional name space simple and avoids accidental
// "bidichan listen ./foo" misinterpretations.
func peelProfileArg(args []string) (string, []string) {
	if len(args) == 0 {
		return "", args
	}
	first := args[0]
	if first == "" || strings.HasPrefix(first, "-") {
		return "", args
	}
	// Path-shaped tokens are not allowed as positional profiles to
	// avoid swallowing accidental relative paths. Operators who want a
	// literal path should use --config instead.
	if strings.ContainsAny(first, "/\\") || strings.HasPrefix(first, "~") || strings.HasSuffix(first, ".conf") {
		return "", args
	}
	return first, args[1:]
}
