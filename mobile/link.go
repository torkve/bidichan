//go:build ios || android

package mobile

import (
	"encoding/json"
	"errors"

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
//
// The field names avoid runs of capitals on purpose. The binding lowercases a
// leading acronym in ways that are easy to get wrong from the other side —
// TUNCIDR would arrive as `tuncidr` — and two languages have to spell every one
// of these correctly, so each name is plain camel case instead.
type ProfileLink struct {
	Name         string
	Addr         string
	Hostname     string
	Path         string
	NoTlsBinding bool
	CaCertPem    string

	EnableTun  bool
	TunCidr    string
	TunCidr6   string
	TunMtu     int
	FullTunnel bool

	MemoryLimitMb      int
	ResumeGraceSeconds int

	// ChannelsJson is the profile's default channels, as the array both
	// clients already persist: label, kind, allInterfaces, port, target,
	// routeSystem. Empty means none.
	ChannelsJson string

	// PskHex is the pre-shared key, and is optional.
	//
	// A link carrying it is a credential: whoever holds the link can use the
	// tunnel. Nothing here protects it — the encoding is reversible by design
	// — so ask before including it, and say so when one arrives.
	PskHex string
}

// NewProfileLink returns an empty link to fill in.
func NewProfileLink() *ProfileLink { return &ProfileLink{} }

// HasSecret reports whether the pre-shared key is included.
func (p *ProfileLink) HasSecret() bool { return p.PskHex != "" }

// Encode renders the shareable link, refusing a profile that could not be
// imported on the other side.
func (p *ProfileLink) Encode() (string, error) {
	l := &profilelink.Link{
		Name:               p.Name,
		Addr:               p.Addr,
		Host:               p.Hostname,
		Path:               p.Path,
		NoTLSBinding:       p.NoTlsBinding,
		CACertPEM:          p.CaCertPem,
		EnableTUN:          p.EnableTun,
		TUNCIDR:            p.TunCidr,
		TUNCIDR6:           p.TunCidr6,
		TUNMTU:             p.TunMtu,
		FullTunnel:         p.FullTunnel,
		MemoryLimitMB:      p.MemoryLimitMb,
		ResumeGraceSeconds: p.ResumeGraceSeconds,
		PSKHex:             p.PskHex,
	}
	if p.ChannelsJson != "" {
		// The raw decoder error names Go types and byte offsets, and this string
		// is shown to whoever pressed Share. It cannot be their fault either —
		// the client composed this JSON — so say what happened, not how.
		if err := json.Unmarshal([]byte(p.ChannelsJson), &l.Channels); err != nil {
			return "", errors.New("profile link: the default channels could not be read")
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
		NoTlsBinding:       l.NoTLSBinding,
		CaCertPem:          l.CACertPEM,
		EnableTun:          l.EnableTUN,
		TunCidr:            l.TUNCIDR,
		TunCidr6:           l.TUNCIDR6,
		TunMtu:             l.TUNMTU,
		FullTunnel:         l.FullTunnel,
		MemoryLimitMb:      l.MemoryLimitMB,
		ResumeGraceSeconds: l.ResumeGraceSeconds,
		PskHex:             l.PSKHex,
	}
	if len(l.Channels) > 0 {
		b, err := json.Marshal(l.Channels)
		if err != nil {
			return nil, errors.New("profile link: the default channels could not be passed on")
		}
		out.ChannelsJson = string(b)
	}
	return out, nil
}

// ProfileLinkPrefix is what a client registers with its platform so a link
// opens the app, and what it matches before offering to import one.
func ProfileLinkPrefix() string {
	return profilelink.Scheme + "://" + profilelink.Host
}
