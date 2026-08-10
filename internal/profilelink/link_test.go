package profilelink

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func sample() *Link {
	return &Link{
		Name:               "gate",
		Addr:               "gate.example.com:443",
		Host:               "gate.example.com",
		Path:               "/events",
		NoTLSBinding:       true,
		Fingerprint:        "ios",
		EnableTUN:          true,
		TUNCIDR:            "10.42.0.2/24",
		TUNCIDR6:           "fd00:bd::2/64",
		TUNMTU:             1400,
		ResumeGraceSeconds: 90,
		Channels: []Channel{
			{Label: "web", Kind: "http", Port: 3128, RouteSystem: true},
			{Kind: "forwardLocal", Port: 8080, Target: "10.0.0.5:80"},
		},
	}
}

func TestRoundTrip(t *testing.T) {
	in := sample()
	raw, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.HasPrefix(raw, "bidichan://profile#") {
		t.Fatalf("unexpected shape: %s", raw)
	}
	out, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	in.Version = Version
	if got, want := mustJSON(t, out), mustJSON(t, in); got != want {
		t.Fatalf("round trip changed the profile:\n got %s\nwant %s", got, want)
	}
}

// The payload has to sit in the fragment: a fragment is never sent to a server,
// so a link pasted into a browser does not leave the device in a request.
func TestPayloadIsInTheFragment(t *testing.T) {
	raw, err := sample().Encode()
	if err != nil {
		t.Fatal(err)
	}
	before, after, found := strings.Cut(raw, "#")
	if !found || after == "" {
		t.Fatal("no fragment")
	}
	if strings.Contains(before, "gate.example.com") {
		t.Fatalf("the address leaked outside the fragment: %s", before)
	}
}

// A link that carries the key is a credential, and both clients decide what to
// say about it from this.
func TestHasSecret(t *testing.T) {
	l := sample()
	if l.HasSecret() {
		t.Fatal("a profile without a key reported one")
	}
	l.PSKHex = "0011223344"
	raw, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !out.HasSecret() || out.PSKHex != "0011223344" {
		t.Fatal("the key did not survive the round trip")
	}
}

// A profile shared twice must not be able to overwrite an unrelated one, so no
// identifier travels in the link.
func TestCarriesNoIdentifier(t *testing.T) {
	raw, err := sample().Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, frag, _ := strings.Cut(raw, "#")
	payload, err := base64.RawURLEncoding.DecodeString(frag)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(payload, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "uuid", "ID"} {
		if _, ok := generic[key]; ok {
			t.Fatalf("the link carries %q", key)
		}
	}
}

func TestRejectsRubbish(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"another scheme":   "https://example.com/#abc",
		"another host":     "bidichan://something#abc",
		"no payload":       "bidichan://profile",
		"truncated base64": "bidichan://profile#not_base64!!",
		"not json":         "bidichan://profile#" + base64.RawURLEncoding.EncodeToString([]byte("hello")),
	}
	for name, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A link from a version that knows fields this one does not must be refused
// clearly, rather than imported as a profile missing whatever it did not
// understand.
func TestRejectsAnotherVersion(t *testing.T) {
	l := sample()
	l.Version = Version + 1
	payload, _ := json.Marshal(l)
	raw := "bidichan://profile#" + base64.RawURLEncoding.EncodeToString(payload)
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("a future version was accepted")
	}
	if !strings.Contains(err.Error(), "newer") {
		t.Fatalf("the error should say which side is newer: %v", err)
	}
}

// Validation happens on the way out too: a link that cannot be imported is
// worse than none, because it fails on someone else's device.
func TestEncodeRefusesAnUnusableProfile(t *testing.T) {
	cases := map[string]func(*Link){
		"no address":        func(l *Link) { l.Addr = "" },
		"no hostname":       func(l *Link) { l.Host = "" },
		"address no port":   func(l *Link) { l.Addr = "gate.example.com" },
		"unknown kind":      func(l *Link) { l.Channels[0].Kind = "telnet" },
		"port out of range": func(l *Link) { l.Channels[0].Port = 70000 },
		"forward no port":   func(l *Link) { l.Channels[1].Target = "10.0.0.5" },
	}
	for name, break_ := range cases {
		l := sample()
		break_(l)
		if _, err := l.Encode(); err == nil {
			t.Errorf("%s: encoded anyway", name)
		}
	}
}

// Both clients persist these names already; changing one would silently break
// links between the two, so pin them.
func TestWireNamesAreStable(t *testing.T) {
	raw, err := sample().Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, frag, _ := strings.Cut(raw, "#")
	payload, _ := base64.RawURLEncoding.DecodeString(frag)
	var generic map[string]any
	if err := json.Unmarshal(payload, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"v", "name", "addr", "host", "path", "noBind", "fp",
		"tun", "cidr", "cidr6", "mtu", "grace", "chans"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("the payload lost the %q field", key)
		}
	}
	chans, ok := generic["chans"].([]any)
	if !ok || len(chans) == 0 {
		t.Fatal("no channels in the payload")
	}
	first, _ := chans[0].(map[string]any)
	for _, key := range []string{"kind", "port", "allInterfaces", "routeSystem"} {
		if _, ok := first[key]; !ok {
			t.Errorf("a channel lost the %q field", key)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
