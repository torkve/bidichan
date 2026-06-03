package channel

import (
	"strings"
	"testing"

	"github.com/torkve/bidichan/internal/peer"
)

func TestSanitizeTUNSpec(t *testing.T) {
	cases := []struct {
		name   string
		in     peer.TUNSpec
		ok     bool
		errSub string // substring expected in the error when ok=false
	}{
		{
			name: "empty is fine (all fields optional)",
			in:   peer.TUNSpec{},
			ok:   true,
		},
		{
			name: "ordinary linux name",
			in:   peer.TUNSpec{Name: "tun0", CIDR: "10.42.0.1/24", MTU: 1400},
			ok:   true,
		},
		{
			name:   "leading dash would be argv-injection",
			in:     peer.TUNSpec{Name: "-rf"},
			ok:     false,
			errSub: "invalid interface name",
		},
		{
			name:   "shell metacharacter in name",
			in:     peer.TUNSpec{Name: "tun;rm -rf /"},
			ok:     false,
			errSub: "invalid interface name",
		},
		{
			name:   "space in name",
			in:     peer.TUNSpec{Name: "tun 0"},
			ok:     false,
			errSub: "invalid interface name",
		},
		{
			name:   "newline in name",
			in:     peer.TUNSpec{Name: "tun0\n"},
			ok:     false,
			errSub: "invalid interface name",
		},
		{
			name:   "too long for IFNAMSIZ",
			in:     peer.TUNSpec{Name: "thisistoolong0123"},
			ok:     false,
			errSub: "invalid interface name",
		},
		{
			name:   "garbage CIDR",
			in:     peer.TUNSpec{CIDR: "not a cidr; echo pwned"},
			ok:     false,
			errSub: "invalid CIDR",
		},
		{
			name:   "non-canonical CIDR is rewritten",
			in:     peer.TUNSpec{CIDR: "10.42.0.1/24"},
			ok:     true,
		},
		{
			name:   "MTU below IPv4 minimum",
			in:     peer.TUNSpec{MTU: 30},
			ok:     false,
			errSub: "MTU",
		},
		{
			name:   "MTU above frame cap",
			in:     peer.TUNSpec{MTU: 1 << 20},
			ok:     false,
			errSub: "MTU",
		},
		{
			name:   "negative MTU",
			in:     peer.TUNSpec{MTU: -1},
			ok:     false,
			errSub: "MTU",
		},
		{
			name:   "unspecified CIDR address",
			in:     peer.TUNSpec{CIDR: "0.0.0.0/24"},
			ok:     false,
			errSub: "unusable",
		},
		{
			name:   "multicast CIDR address",
			in:     peer.TUNSpec{CIDR: "224.0.0.1/24"},
			ok:     false,
			errSub: "unusable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := sanitizeTUNSpec(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("expected ok, got error: %v", err)
				}
				// Spot check: CIDR comes back canonical.
				if tc.in.CIDR != "" && out.CIDR == "" {
					t.Fatalf("CIDR was dropped: %q -> %q", tc.in.CIDR, out.CIDR)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got none", tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSub)
				}
			}
		})
	}
}
