// Package profilelink encodes a connection profile as a link, so one device can
// hand its settings to another without either end retyping them.
//
// The format lives here, in the core both clients embed, rather than in each
// client: a link written by one has to be readable by the other, and two
// hand-written implementations would drift the moment either gained a field.
//
// A link looks like:
//
//	bidichan://profile#<base64url of the JSON payload>
//
// The payload rides in the fragment because a fragment is never sent to a
// server: if the link is pasted into a browser instead of the app, it does not
// leave the device in a request. It is not encryption — see PSKHex.
package profilelink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Scheme and Host make up the prefix both clients register with their platform.
const (
	Scheme = "bidichan"
	Host   = "profile"

	// Version is the payload version. A reader that does not know a version
	// refuses the link rather than guessing at its meaning.
	Version = 1

	// MaxBytes caps the link. A real profile, including a CA certificate, is a
	// few kilobytes; this leaves generous room while keeping a link someone
	// sent us from turning into an arbitrary allocation.
	MaxBytes = 64 << 10

	// MaxChannels caps the default channels a link may carry. They are opened
	// on connect, so an unbounded list is an unbounded amount of work asked of
	// the device and the peer.
	MaxChannels = 32
)

// Link is everything needed to recreate a profile elsewhere. It deliberately
// carries no identifier: the importing device makes its own, so importing the
// same link twice cannot overwrite an unrelated profile.
type Link struct {
	Version int    `json:"v"`
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Host    string `json:"host"`
	Path    string `json:"path,omitempty"`

	NoTLSBinding bool   `json:"noBind"`
	Fingerprint  string `json:"fp,omitempty"`
	CACertPEM    string `json:"ca,omitempty"`

	EnableTUN  bool   `json:"tun"`
	TUNCIDR    string `json:"cidr,omitempty"`
	TUNCIDR6   string `json:"cidr6,omitempty"`
	TUNMTU     int    `json:"mtu,omitempty"`
	FullTunnel bool   `json:"full"`

	MemoryLimitMB      int `json:"mem,omitempty"`
	ResumeGraceSeconds int `json:"grace,omitempty"`

	Channels []Channel `json:"chans,omitempty"`

	// PSKHex is the pre-shared key, and is optional. A link that carries it is
	// a credential: anyone holding the link can use the tunnel. Nothing here
	// protects it — the encoding is reversible by design — so a sender should
	// be asked before it is included, and a receiver told when it is present.
	PSKHex string `json:"psk,omitempty"`
}

// Channel mirrors the channel both clients configure. The field names are the
// ones both already persist, so a link is readable by either.
type Channel struct {
	Label         string `json:"label,omitempty"`
	Kind          string `json:"kind"`
	AllInterfaces bool   `json:"allInterfaces"`
	Port          int    `json:"port"`
	Target        string `json:"target,omitempty"`
	RouteSystem   bool   `json:"routeSystem"`
}

// knownKinds are the channel kinds a client may be asked to open. An unknown
// kind is refused rather than imported as something the user did not intend.
var knownKinds = map[string]bool{
	"socks5":        true,
	"http":          true,
	"forwardLocal":  true,
	"forwardRemote": true,
}

// HasSecret reports whether the link carries the pre-shared key, so a client
// can say so before importing or sharing.
func (l *Link) HasSecret() bool { return l.PSKHex != "" }

// Encode renders the link. It validates first: a link that cannot be imported
// is worse than no link, because the failure surfaces on someone else's device.
func (l *Link) Encode() (string, error) {
	c := *l
	c.Version = Version
	if err := c.validate(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(&c)
	if err != nil {
		return "", fmt.Errorf("profile link: %w", err)
	}
	return Scheme + "://" + Host + "#" + base64.RawURLEncoding.EncodeToString(payload), nil
}

// Parse reads a link produced by Encode, on this or any other client.
func Parse(raw string) (*Link, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("profile link: too large (%d bytes, limit %d)", len(raw), MaxBytes)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("profile link: %w", err)
	}
	if !strings.EqualFold(u.Scheme, Scheme) || !strings.EqualFold(u.Host, Host) {
		return nil, fmt.Errorf("profile link: not a %s://%s link", Scheme, Host)
	}
	if u.Fragment == "" {
		return nil, errors.New("profile link: nothing to import")
	}
	payload, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil {
		return nil, errors.New("profile link: damaged (the text was probably truncated)")
	}
	var l Link
	if err := json.Unmarshal(payload, &l); err != nil {
		return nil, errors.New("profile link: damaged (unreadable contents)")
	}
	if l.Version != Version {
		return nil, fmt.Errorf(
			"profile link: made by a %s version of the app (format %d, this one reads %d)",
			newerOrOlder(l.Version), l.Version, Version)
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &l, nil
}

func newerOrOlder(v int) string {
	if v > Version {
		return "newer"
	}
	return "older"
}

// validate rejects a link that would produce a profile which cannot connect,
// or one that should not be acted on at all.
//
// A link arrives from outside — someone sends it — so this is a trust boundary
// in the same sense as a peer-supplied channel spec (see channel.sanitizeTUNSpec),
// and every field that later reaches a socket or the wire is checked here
// rather than where it is used.
func (l *Link) validate() error {
	if l.Addr == "" {
		return errors.New("profile link: no server address")
	}
	if l.Host == "" {
		return errors.New("profile link: no hostname")
	}
	if !strings.Contains(l.Addr, ":") {
		return fmt.Errorf("profile link: server address %q has no port", l.Addr)
	}
	// The transport composes the upgrade request by hand, so a control
	// character in any of these would let whoever wrote the link decide what
	// request the importing device sends — to a host they also chose.
	for _, f := range []struct{ what, value string }{
		{"server address", l.Addr},
		{"hostname", l.Host},
		{"path", l.Path},
		{"fingerprint", l.Fingerprint},
		{"name", l.Name},
	} {
		if hasControl(f.value) {
			return fmt.Errorf("profile link: %s contains a control character", f.what)
		}
	}
	if len(l.Channels) > MaxChannels {
		return fmt.Errorf("profile link: %d channels, limit %d", len(l.Channels), MaxChannels)
	}
	for i, c := range l.Channels {
		if hasControl(c.Target) || hasControl(c.Label) {
			return fmt.Errorf("profile link: channel %d contains a control character", i+1)
		}
		if !knownKinds[c.Kind] {
			return fmt.Errorf("profile link: channel %d has an unknown kind %q", i+1, c.Kind)
		}
		if c.Port < 1 || c.Port > 65535 {
			return fmt.Errorf("profile link: channel %d has an invalid port %d", i+1, c.Port)
		}
		if (c.Kind == "forwardLocal" || c.Kind == "forwardRemote") && !strings.Contains(c.Target, ":") {
			return fmt.Errorf("profile link: channel %d forwards to %q, which has no port", i+1, c.Target)
		}
	}
	return nil
}

// hasControl reports whether s carries anything that is not printable text —
// CR and LF above all, which are what would end one header and begin another.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}
