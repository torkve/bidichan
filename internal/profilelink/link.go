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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
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

	// The MTU bounds mirror channel.sanitizeTUNSpec, so a value that would be
	// refused when the tunnel is set up is refused at import instead.
	minTunMTU = 68
	maxTunMTU = 16384 - 128

	// These two the core does not bound anywhere: it applies whatever it is
	// given. They are this layer's own policy, because a link arrives from
	// someone else and an absurd figure should be refused while it can still be
	// explained rather than becoming a profile that behaves strangely. The
	// memory floor is roughly what the Go runtime needs to not spend its life
	// collecting.
	minMemoryMB  = 16
	maxMemoryMB  = 512
	maxGraceSecs = 3600
)

// Link is everything needed to recreate a profile elsewhere. It deliberately
// carries no identifier: the importing device makes its own, so importing the
// same link twice cannot overwrite an unrelated profile.
type Link struct {
	Version int    `json:"v"`
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Host    string `json:"host"`
	Path    string `json:"path"`

	NoTLSBinding bool   `json:"noBind"`
	CACertPEM    string `json:"ca"`

	EnableTUN  bool   `json:"tun"`
	TUNCIDR    string `json:"cidr"`
	TUNCIDR6   string `json:"cidr6"`
	TUNMTU     int    `json:"mtu"`
	FullTunnel bool   `json:"full"`

	MemoryLimitMB      int `json:"mem"`
	ResumeGraceSeconds int `json:"grace"`

	Channels []Channel `json:"chans"`

	// PSKHex is the pre-shared key, and is optional. A link that carries it is
	// a credential: anyone holding the link can use the tunnel. Nothing here
	// protects it — the encoding is reversible by design — so a sender should
	// be asked before it is included, and a receiver told when it is present.
	PSKHex string `json:"psk"`
}

// Channel mirrors the channel both clients configure. The field names are the
// ones both already persist, so a link is readable by either.
// Every field is emitted even when empty, deliberately: a client whose decoder
// requires each key — Swift's synthesized one does — silently decodes nothing
// when a key it expects is missing, and an absent "target" on a proxy channel
// would cost the importer every channel in the link.
type Channel struct {
	Label         string `json:"label"`
	Kind          string `json:"kind"`
	AllInterfaces bool   `json:"allInterfaces"`
	Port          int    `json:"port"`
	Target        string `json:"target"`
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
	// An empty list, never null. Both clients build this list themselves — iOS
	// sends "[]" for a profile with no channels, Android sends nothing at all —
	// so without this the same profile would encode to two different payloads
	// depending on which device shared it.
	if c.Channels == nil {
		c.Channels = []Channel{}
	}
	payload, err := json.Marshal(&c)
	if err != nil {
		return "", fmt.Errorf("profile link: %w", err)
	}
	link := Scheme + "://" + Host + "#" + base64.RawURLEncoding.EncodeToString(payload)
	// The same limit Parse applies, checked here so the refusal lands on the
	// device that can still do something about it. A pasted CA bundle is the
	// way to reach it: nothing else here is unbounded.
	if len(link) > MaxBytes {
		return "", fmt.Errorf("profile link: too large (%d bytes, limit %d)", len(link), MaxBytes)
	}
	return link, nil
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
	if l.Version < 1 {
		return nil, errors.New("profile link: damaged (no format version)")
	}
	// Older links stay readable — that is what a version is for. Only a format
	// from the future is refused, because we cannot know what it means.
	if l.Version > Version {
		return nil, fmt.Errorf(
			"profile link: made by a newer version of the app (format %d, this one reads %d)",
			l.Version, Version)
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &l, nil
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
	// Character checks first, so a poisoned value is reported as what it is
	// rather than as whatever it happens to also fail.
	//
	// The transport composes the upgrade request by hand, so a control
	// character in any of these would let whoever wrote the link decide what
	// request the importing device sends — to a host they also chose. A space
	// is not a control character but is just as unwelcome in the three that end
	// up in the request: it ends the target in the request line, and makes a
	// header malformed. None of these can legitimately contain either.
	for _, f := range []struct {
		what      string
		value     string
		inRequest bool
	}{
		{"server address", l.Addr, true},
		{"hostname", l.Host, true},
		{"path", l.Path, true},
		{"name", l.Name, false},
	} {
		if hasControl(f.value) {
			return fmt.Errorf("profile link: %s contains a control character", f.what)
		}
		if f.inRequest && strings.Contains(f.value, " ") {
			return fmt.Errorf("profile link: %s %q contains a space", f.what, f.value)
		}
	}
	if err := checkHostPort("server address", l.Addr, true); err != nil {
		return err
	}
	// Anything not rooted at / is either a broken request or an absolute-form
	// one, which a reverse proxy may route somewhere other than the origin the
	// importer thinks they are getting.
	if l.Path != "" && !strings.HasPrefix(l.Path, "/") {
		return fmt.Errorf("profile link: path %q does not start with /", l.Path)
	}
	// Values that would be refused, or would simply behave oddly, once the
	// profile is used. Catching them here means a link is rejected while it can
	// still be explained, rather than becoming a profile that fails later.
	if l.PSKHex != "" {
		if _, err := hex.DecodeString(l.PSKHex); err != nil {
			return errors.New("profile link: the key is not valid hex")
		}
	}
	if l.TUNMTU != 0 && (l.TUNMTU < minTunMTU || l.TUNMTU > maxTunMTU) {
		return fmt.Errorf("profile link: MTU %d is outside %d-%d", l.TUNMTU, minTunMTU, maxTunMTU)
	}
	// The same rules channel.sanitizeTUNSpec applies, and for the same reason:
	// ParseCIDR survives values that are unusable as a point-to-point address,
	// and an IPv4 address in the IPv6 field is the copy-paste this catches.
	for _, c := range []struct {
		what  string
		value string
		v6    bool
	}{
		{"address", l.TUNCIDR, false},
		{"IPv6 address", l.TUNCIDR6, true},
	} {
		if c.value == "" {
			continue
		}
		ip, _, err := net.ParseCIDR(c.value)
		if err != nil {
			return fmt.Errorf("profile link: tunnel %s %q is not a CIDR", c.what, c.value)
		}
		if c.v6 && ip.To4() != nil {
			return fmt.Errorf("profile link: tunnel %s %q is an IPv4 address", c.what, c.value)
		}
		if ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("profile link: tunnel %s %q cannot be assigned to a device", c.what, c.value)
		}
	}
	if l.MemoryLimitMB != 0 && (l.MemoryLimitMB < minMemoryMB || l.MemoryLimitMB > maxMemoryMB) {
		return fmt.Errorf("profile link: memory limit %d MB is outside %d-%d",
			l.MemoryLimitMB, minMemoryMB, maxMemoryMB)
	}
	if l.ResumeGraceSeconds < 0 || l.ResumeGraceSeconds > maxGraceSecs {
		return fmt.Errorf("profile link: reconnect window %ds is outside 0-%d",
			l.ResumeGraceSeconds, maxGraceSecs)
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
		// A forward's target is dialed on whichever side opens it (see
		// daemon.ctrlOpenForward), with nothing between here and the dial, so
		// it gets the same treatment as the server address. An empty host is
		// allowed — ":80" means the loopback of the far side.
		if c.Kind == "forwardLocal" || c.Kind == "forwardRemote" {
			if err := checkHostPort(fmt.Sprintf("channel %d target", i+1), c.Target, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkHostPort rejects anything that is not a dialable host:port. requireHost
// is false where an empty host is meaningful, as it is for a forward target.
func checkHostPort(what, value string, requireHost bool) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("profile link: %s %q is not host:port", what, value)
	}
	if requireHost && host == "" {
		return fmt.Errorf("profile link: %s %q has no host", what, value)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("profile link: %s %q has no usable port", what, value)
	}
	return nil
}

// hasControl reports whether s carries anything that is not printable text —
// CR and LF above all, which are what would end one header and begin another.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}
