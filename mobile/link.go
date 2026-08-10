//go:build ios || android

package mobile

import (
	"encoding/json"
	"fmt"

	"github.com/torkve/bidichan/internal/profilelink"
)

// ProfileLink shares a profile with another device: one client encodes its
// settings into a link, another decodes them. Both clients use this same
// implementation, so a link written by either is readable by the other.
//
// The type is built for the binding: scalars only, with the channel list riding
// as JSON, because a list of structs cannot cross into Swift or Kotlin. The
// JSON is validated here, so a malformed channel is refused on the way out
// rather than surfacing on someone else's device.
type ProfileLink struct {
	Name         string
	Addr         string
	Hostname     string
	Path         string
	NoTLSBinding bool
	Fingerprint  string
	CACertPEM    string

	EnableTUN  bool
	TUNCIDR    string
	TUNCIDR6   string
	TUNMTU     int
	FullTunnel bool

	MemoryLimitMB      int
	ResumeGraceSeconds int

	// ChannelsJSON is the profile's default channels, as the array both
	// clients already persist: label, kind, allInterfaces, port, target,
	// routeSystem. Empty means none.
	ChannelsJSON string

	// PSKHex is the pre-shared key, and is optional.
	//
	// A link carrying it is a credential: whoever holds the link can use the
	// tunnel. Nothing here protects it — the encoding is reversible by design
	// — so ask before including it, and say so when one arrives.
	PSKHex string
}

// NewProfileLink returns an empty link to fill in.
func NewProfileLink() *ProfileLink { return &ProfileLink{} }

// HasSecret reports whether the pre-shared key is included.
func (p *ProfileLink) HasSecret() bool { return p.PSKHex != "" }

// Encode renders the shareable link, refusing a profile that could not be
// imported on the other side.
func (p *ProfileLink) Encode() (string, error) {
	l := &profilelink.Link{
		Name:               p.Name,
		Addr:               p.Addr,
		Host:               p.Hostname,
		Path:               p.Path,
		NoTLSBinding:       p.NoTLSBinding,
		Fingerprint:        p.Fingerprint,
		CACertPEM:          p.CACertPEM,
		EnableTUN:          p.EnableTUN,
		TUNCIDR:            p.TUNCIDR,
		TUNCIDR6:           p.TUNCIDR6,
		TUNMTU:             p.TUNMTU,
		FullTunnel:         p.FullTunnel,
		MemoryLimitMB:      p.MemoryLimitMB,
		ResumeGraceSeconds: p.ResumeGraceSeconds,
		PSKHex:             p.PSKHex,
	}
	if p.ChannelsJSON != "" {
		if err := json.Unmarshal([]byte(p.ChannelsJSON), &l.Channels); err != nil {
			return "", fmt.Errorf("profile link: channels: %w", err)
		}
	}
	return l.Encode()
}

// ParseProfileLink reads a link produced by this or any other client. The Go
// error carries a message meant to be shown as-is.
func ParseProfileLink(raw string) (*ProfileLink, error) {
	l, err := profilelink.Parse(raw)
	if err != nil {
		return nil, err
	}
	out := &ProfileLink{
		Name:               l.Name,
		Addr:               l.Addr,
		Hostname:           l.Host,
		Path:               l.Path,
		NoTLSBinding:       l.NoTLSBinding,
		Fingerprint:        l.Fingerprint,
		CACertPEM:          l.CACertPEM,
		EnableTUN:          l.EnableTUN,
		TUNCIDR:            l.TUNCIDR,
		TUNCIDR6:           l.TUNCIDR6,
		TUNMTU:             l.TUNMTU,
		FullTunnel:         l.FullTunnel,
		MemoryLimitMB:      l.MemoryLimitMB,
		ResumeGraceSeconds: l.ResumeGraceSeconds,
		PSKHex:             l.PSKHex,
	}
	if len(l.Channels) > 0 {
		b, err := json.Marshal(l.Channels)
		if err != nil {
			return nil, fmt.Errorf("profile link: channels: %w", err)
		}
		out.ChannelsJSON = string(b)
	}
	return out, nil
}

// ProfileLinkPrefix is what a client registers with its platform so a link
// opens the app, and what it matches before offering to import one.
func ProfileLinkPrefix() string {
	return profilelink.Scheme + "://" + profilelink.Host
}
