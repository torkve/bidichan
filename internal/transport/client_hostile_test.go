package transport

import (
	"context"
	"strings"
	"testing"
)

// The upgrade request is composed by hand, so a value that ends a line would
// let whoever supplied it compose the request instead of us. These reach the
// transport from a config file, a command line, or a profile someone shared,
// so the dial refuses them rather than trusting the caller to have checked.
func TestDialRefusesControlCharacters(t *testing.T) {
	psk := []byte("0123456789abcdef")
	cases := map[string]ClientConfig{
		"hostname": {Hostname: "gate.example.com\r\nX-Injected: 1", PSK: psk},
		"path":     {Hostname: "gate.example.com", PSK: psk, Path: "/x HTTP/1.1\r\nX: 1"},
		"tab":      {Hostname: "gate.example.com", PSK: psk, Path: "/a\tb"},
	}
	for name, cfg := range cases {
		// 0.0.0.0:1 never connects; the point is that we fail before dialling.
		_, err := Dial(context.Background(), "127.0.0.1:1", cfg)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "control character") {
			t.Errorf("%s: failed for the wrong reason: %v", name, err)
		}
	}
}
