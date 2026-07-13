//go:build ios

package mobile

import (
	"fmt"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Config carries the connect-side settings for the mobile client. Every field
// is a gomobile-bindable scalar or []byte so the struct crosses cleanly into
// Swift. Build one with NewConfig, set the fields, and pass it to Client.Start.
type Config struct {
	// Addr is the server host:port (e.g. "ws.example.com:443").
	Addr string
	// Hostname is the SNI and the HTTP Host header.
	Hostname string
	// PSKHex is the hex-encoded pre-shared key (same value as the server).
	PSKHex string
	// Path is the WebSocket upgrade path; empty derives it from the PSK.
	Path string
	// NoTLSBinding drops the certificate channel binding from auth. Set true
	// when the server sits behind a TLS-terminating reverse proxy (the common
	// nginx deployment).
	NoTLSBinding bool
	// CACertPEM optionally pins the server to a PEM CA bundle. Empty uses the
	// system trust store.
	CACertPEM []byte
	// Fingerprint selects the uTLS ClientHello to mimic: "ios" (default),
	// "safari", or "chrome".
	Fingerprint string
	// MemoryLimitMB sets a soft Go heap limit (runtime/debug.SetMemoryLimit) so
	// the runtime stays under the Network Extension's memory cap. 0 leaves it
	// unset.
	MemoryLimitMB int
}

// NewConfig returns a Config with iOS-appropriate defaults.
func NewConfig() *Config {
	return &Config{Fingerprint: "ios"}
}

// fingerprintID maps the Config.Fingerprint string to a uTLS ClientHelloID.
// The empty string defaults to iOS, matching what an iPhone should present.
func fingerprintID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "ios":
		return utls.HelloIOS_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "chrome":
		return utls.HelloChrome_Auto, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unknown fingerprint %q (want ios|safari|chrome)", name)
	}
}
