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

// testCAPEM is a fixed self-signed certificate. It has to be a real one —
// validate loads it the same way the tunnel does — and it has to be this exact
// one rather than freshly generated, because the golden payload below includes
// it byte for byte. Nothing signs anything with it; it is only ever parsed.
const testCAPEM = "-----BEGIN CERTIFICATE-----\n" +
	"MIIBbTCCAROgAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDExpiaWRpY2hh\n" +
	"biBwcm9maWxlIGxpbmsgdGVzdDAgFw03MDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAw\n" +
	"MDAwMFowJTEjMCEGA1UEAxMaYmlkaWNoYW4gcHJvZmlsZSBsaW5rIHRlc3QwWTAT\n" +
	"BgcqhkjOPQIBBggqhkjOPQMBBwNCAATWYNQsSLxMXetVm6rd3LM+Du7RrK2dlhbh\n" +
	"YwQt0fEfU/iAuYj5u+DOR0d6b1rFfHu5pgJZf/aIl9+7QLvHEObSozIwMDAPBgNV\n" +
	"HRMBAf8EBTADAQH/MB0GA1UdDgQWBBSX6+WQBsk6NbSSbPLqySLBwCBYJTAKBggq\n" +
	"hkjOPQQDAgNIADBFAiBvfp0g+aaQkNgeBwKGYBzAKSc44zokFCalGBxn29TsmgIh\n" +
	"ALbTTGwfL5w6zbSakqKpm6ImZRumf72QShZHajHqIgQu\n" +
	"-----END CERTIFICATE-----\n"

// everything is a link with every field set, so nothing can go unnoticed by
// being zero.
func everything() *Link {
	return &Link{
		Name:               "gate",
		Addr:               "gate.example.com:443",
		Host:               "gate.example.com",
		Path:               "/events",
		NoTLSBinding:       true,
		CACertPEM:          testCAPEM,
		EnableTUN:          true,
		TUNCIDR:            "10.42.0.2/24",
		TUNCIDR6:           "fd00:bd::2/64",
		TUNMTU:             1400,
		FullTunnel:         true,
		MemoryLimitMB:      40,
		ResumeGraceSeconds: 90,
		Channels: []Channel{
			{Label: "web", Kind: "http", AllInterfaces: true, Port: 3128, RouteSystem: true},
			{Kind: "forwardLocal", Port: 8080, Target: "10.0.0.5:80"},
		},
		PSKHex: "0011223344",
	}
}

// The payload both clients read, byte for byte.
//
// This is a golden comparison rather than a list of expected keys because the
// two clients spell these names by hand: a renamed tag, a dropped field, a
// reordering that a keys-present check would let through is a link one client
// writes and the other cannot read. Note the second channel — every key is
// present even though its label and routeSystem are empty, which is what keeps
// a strict decoder on the other side from throwing the channel away.
//
// Changing this string is changing the format — bump Version with it. The one
// exception is the certificate: it is a fixture, not part of the format, so if
// it ever has to be replaced, update it here and in testCAPEM together and
// leave Version alone.
const goldenPayload = `{"v":1,"name":"gate","addr":"gate.example.com:443","host":"gate.example.com",` +
	`"path":"/events","noBind":true,"ca":"` +
	`-----BEGIN CERTIFICATE-----\n` +
	`MIIBbTCCAROgAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDExpiaWRpY2hh\n` +
	`biBwcm9maWxlIGxpbmsgdGVzdDAgFw03MDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAw\n` +
	`MDAwMFowJTEjMCEGA1UEAxMaYmlkaWNoYW4gcHJvZmlsZSBsaW5rIHRlc3QwWTAT\n` +
	`BgcqhkjOPQIBBggqhkjOPQMBBwNCAATWYNQsSLxMXetVm6rd3LM+Du7RrK2dlhbh\n` +
	`YwQt0fEfU/iAuYj5u+DOR0d6b1rFfHu5pgJZf/aIl9+7QLvHEObSozIwMDAPBgNV\n` +
	`HRMBAf8EBTADAQH/MB0GA1UdDgQWBBSX6+WQBsk6NbSSbPLqySLBwCBYJTAKBggq\n` +
	`hkjOPQQDAgNIADBFAiBvfp0g+aaQkNgeBwKGYBzAKSc44zokFCalGBxn29TsmgIh\n` +
	`ALbTTGwfL5w6zbSakqKpm6ImZRumf72QShZHajHqIgQu\n` +
	`-----END CERTIFICATE-----\n",` +
	`"tun":true,"cidr":"10.42.0.2/24","cidr6":"fd00:bd::2/64","mtu":1400,"full":true,"mem":40,"grace":90,` +
	`"chans":[{"label":"web","kind":"http","allInterfaces":true,"port":3128,"target":"","routeSystem":true},` +
	`{"label":"","kind":"forwardLocal","allInterfaces":false,"port":8080,"target":"10.0.0.5:80","routeSystem":false}],` +
	`"psk":"0011223344"}`

func TestTheWireFormatIsExactlyThis(t *testing.T) {
	raw, err := everything().Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, want := payloadOf(t, raw), goldenPayload
	if got == want {
		return
	}
	// Both are one long line, and the certificate in the middle makes them
	// unreadable side by side. Point at where they diverge instead.
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	t.Fatalf("the wire format changed — the other client cannot read this.\n"+
		"first difference at byte %d\n got %s\nwant %s",
		i, excerptAround(got, i), excerptAround(want, i))
}

// excerptAround returns the 60 bytes on either side of i, so a golden failure
// shows the part that differs rather than a kilobyte of certificate.
func excerptAround(s string, i int) string {
	const window = 60
	start, end := max(0, i-window), min(len(s), i+window)
	out := s[start:end]
	if start > 0 {
		out = "…" + out
	}
	if end < len(s) {
		out += "…"
	}
	return out
}

// A channel carries all six keys even when five of them are empty. Without
// this, a decoder that requires each key — Swift's synthesized one — throws,
// and the client that swallows the error imports a profile with no channels at
// all. Asserted on the type directly so it holds however a link is built.
func TestAChannelAlwaysCarriesEveryKey(t *testing.T) {
	b, err := json.Marshal(Channel{Kind: "http", Port: 3128})
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"label", "kind", "allInterfaces", "port", "target", "routeSystem"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("an empty channel omits %q: %s", key, b)
		}
	}
	if len(generic) != 6 {
		t.Errorf("a channel gained a field: %s", b)
	}
}

// A profile with no default channels must send an empty array, not null: a
// decoder expecting an array throws on null, and would lose the whole link over
// a profile that simply has no channels.
func TestNoChannelsIsAnEmptyArray(t *testing.T) {
	l := sample()
	l.Channels = nil
	raw, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if payload := payloadOf(t, raw); !strings.Contains(payload, `"chans":[]`) {
		t.Fatalf("channels were not an empty array: %s", payload)
	}
}

// A version is only useful if old links keep working; only one from the future
// is refused, since we cannot know what it means.
//
// While Version is 1 this asserts only that format 1 is readable. It becomes
// the real check the moment Version is bumped — leave the literal 1 here rather
// than following Version up, and add the new number as a second case.
func TestAcceptsAnOlderVersion(t *testing.T) {
	l := everything()
	l.Version = 1
	payload, _ := json.Marshal(l)
	raw := "bidichan://profile#" + base64.RawURLEncoding.EncodeToString(payload)
	if _, err := Parse(raw); err != nil {
		t.Fatalf("refused a link from format 1: %v", err)
	}
}

// A link arrives from outside, and every field here ends up in a socket call, a
// request line, or a system route. What the rest of the core would refuse later
// is refused now, while it can still be explained.
func TestRefusesValuesTheCoreWouldNotAccept(t *testing.T) {
	cases := map[string]func(*Link){
		"port not a number":    func(l *Link) { l.Addr = "gate.example.com:https" },
		"port zero":            func(l *Link) { l.Addr = "gate.example.com:0" },
		"port too large":       func(l *Link) { l.Addr = "gate.example.com:70000" },
		"no host in address":   func(l *Link) { l.Addr = ":443" },
		"space in address":     func(l *Link) { l.Addr = "gate.example .com:443" },
		"space in hostname":    func(l *Link) { l.Host = "gate.example .com" },
		"path not rooted":      func(l *Link) { l.Path = "events" },
		"path absolute-form":   func(l *Link) { l.Path = "http://elsewhere.example.com/events" },
		"path with a space":    func(l *Link) { l.Path = "/e vents" },
		"key not hex":          func(l *Link) { l.PSKHex = "zzzz" },
		"key odd length":       func(l *Link) { l.PSKHex = "abc" },
		"mtu below the floor":  func(l *Link) { l.TUNMTU = minTunMTU - 1 },
		"mtu above the roof":   func(l *Link) { l.TUNMTU = maxTunMTU + 1 },
		"address not a CIDR":   func(l *Link) { l.TUNCIDR = "10.42.0.2" },
		"v6 address not CIDR":  func(l *Link) { l.TUNCIDR6 = "fd00:bd::2" },
		"memory below the min": func(l *Link) { l.MemoryLimitMB = minMemoryMB - 1 },
		"memory above the max": func(l *Link) { l.MemoryLimitMB = maxMemoryMB + 1 },
		"negative grace":       func(l *Link) { l.ResumeGraceSeconds = -1 },
		"grace beyond the cap": func(l *Link) { l.ResumeGraceSeconds = maxGraceSecs + 1 },

		// The rules channel.sanitizeTUNSpec applies once the tunnel is set up.
		// ParseCIDR survives all of these; the device cannot use any of them.
		"IPv4 in the v6 field": func(l *Link) { l.TUNCIDR6 = "10.42.0.2/24" },
		"unspecified address":  func(l *Link) { l.TUNCIDR = "0.0.0.0/0" },
		"multicast address":    func(l *Link) { l.TUNCIDR = "224.0.0.1/24" },
		"unspecified v6":       func(l *Link) { l.TUNCIDR6 = "::/0" },
		"multicast v6":         func(l *Link) { l.TUNCIDR6 = "ff02::1/64" },

		// A forward's target is dialed with nothing between the link and the
		// dial, so it gets the same treatment as the server address.
		"target not host:port": func(l *Link) { l.Channels[1].Target = "10.0.0.5" },
		"target port zero":     func(l *Link) { l.Channels[1].Target = "10.0.0.5:0" },
		"target port too big":  func(l *Link) { l.Channels[1].Target = "10.0.0.5:99999" },
		"target no port":       func(l *Link) { l.Channels[1].Target = "10.0.0.5:" },
		"target v6 unbrack.":   func(l *Link) { l.Channels[1].Target = "fd00::1:80" },
		"space in target":      func(l *Link) { l.Channels[1].Target = "10.0.0.5 :80" },
	}
	for name, poison := range cases {
		l := everything()
		poison(l)
		if _, err := l.Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
		// And a payload someone else built, since a link does not have to have
		// come from Encode.
		l.Version = Version
		payload, _ := json.Marshal(l)
		raw := "bidichan://profile#" + base64.RawURLEncoding.EncodeToString(payload)
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// The values above are refused; these have to keep working, or the check is
// just a way to reject good profiles.
func TestAcceptsTheEdgesThatAreAllowed(t *testing.T) {
	cases := map[string]func(*Link){
		"no path":           func(l *Link) { l.Path = "" },
		"no key":            func(l *Link) { l.PSKHex = "" },
		"no tun addresses":  func(l *Link) { l.TUNCIDR, l.TUNCIDR6 = "", "" },
		"unset mtu":         func(l *Link) { l.TUNMTU = 0 },
		"unset memory":      func(l *Link) { l.MemoryLimitMB = 0 },
		"zero grace":        func(l *Link) { l.ResumeGraceSeconds = 0 },
		"lowest port":       func(l *Link) { l.Addr = "gate.example.com:1" },
		"highest port":      func(l *Link) { l.Addr = "gate.example.com:65535" },
		"literal v6 addr":   func(l *Link) { l.Addr = "[fd00:bd::1]:443" },
		"mtu at the floor":  func(l *Link) { l.TUNMTU = minTunMTU },
		"mtu at the roof":   func(l *Link) { l.TUNMTU = maxTunMTU },
		"grace at the cap":  func(l *Link) { l.ResumeGraceSeconds = maxGraceSecs },
		"memory at the min": func(l *Link) { l.MemoryLimitMB = minMemoryMB },
		// ":80" is a legitimate forward target: the far side's own loopback.
		"target with no host": func(l *Link) { l.Channels[1].Target = ":80" },
		"target v6 bracketed": func(l *Link) { l.Channels[1].Target = "[fd00::1]:80" },
	}
	for name, adjust := range cases {
		l := everything()
		adjust(l)
		raw, err := l.Encode()
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if _, err := Parse(raw); err != nil {
			t.Errorf("%s: encoded but would not parse: %v", name, err)
		}
	}
}

func payloadOf(t *testing.T, raw string) string {
	t.Helper()
	_, frag, found := strings.Cut(raw, "#")
	if !found {
		t.Fatalf("no fragment in %s", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(frag)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A link is something someone else sent. The transport composes the upgrade
// request by hand, so a control character in any field that reaches it would
// let the link's author decide what request the importing device sends — to a
// host they also chose. None of these may survive.
func TestRefusesControlCharacters(t *testing.T) {
	cases := map[string]func(*Link){
		"path":     func(l *Link) { l.Path = "/x HTTP/1.1\r\nX-Injected: 1\r\nGET /" },
		"hostname": func(l *Link) { l.Host = "gate.example.com\r\nX-Injected: 1" },
		"address":  func(l *Link) { l.Addr = "gate.example.com:443\r\n" },
		"name":     func(l *Link) { l.Name = "a\nb" },
		"target":   func(l *Link) { l.Channels[1].Target = "10.0.0.5:80\r\nX: 1" },
		"label":    func(l *Link) { l.Channels[0].Label = "a\r\nb" },
		"tab":      func(l *Link) { l.Path = "/a\tb" },
	}
	for name, poison := range cases {
		l := sample()
		poison(l)
		if _, err := l.Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
		// And a hand-built payload must not get in either, since a link does
		// not have to have been produced by Encode.
		l.Version = Version
		payload, _ := json.Marshal(l)
		raw := "bidichan://profile#" + base64.RawURLEncoding.EncodeToString(payload)
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// The channels in a link are opened on connect, so an unbounded list is an
// unbounded amount of work asked of the device and the peer.
func TestRefusesTooManyChannels(t *testing.T) {
	l := sample()
	l.Channels = make([]Channel, MaxChannels+1)
	for i := range l.Channels {
		l.Channels[i] = Channel{Kind: "http", Port: 3128}
	}
	if _, err := l.Encode(); err == nil {
		t.Fatal("encoded a link with more channels than the limit")
	}
	l.Channels = l.Channels[:MaxChannels]
	if _, err := l.Encode(); err != nil {
		t.Fatalf("refused a link at exactly the limit: %v", err)
	}
}

// Nothing should turn a link someone sent into an arbitrary allocation.
func TestRefusesAnOversizedLink(t *testing.T) {
	huge := "bidichan://profile#" + strings.Repeat("A", MaxBytes)
	if _, err := Parse(huge); err == nil {
		t.Fatal("parsed an oversized link")
	}
}

// And the sender is told, rather than the link failing on the device that
// received it. A pasted CA bundle is the realistic way to reach this, being
// the largest thing a profile carries. It has to be a real one, or it would be
// refused for being junk before its size ever mattered.
func TestEncodeRefusesALinkTooBigToImport(t *testing.T) {
	l := sample()
	l.CACertPEM = strings.Repeat(testCAPEM, MaxBytes/len(testCAPEM)+2)
	raw, err := l.Encode()
	if err == nil {
		if _, perr := Parse(raw); perr != nil {
			t.Fatalf("encoded a link its own Parse refuses: %v", perr)
		}
		t.Fatal("encoded an oversized link")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("the error should say what is wrong: %v", err)
	}
}

// A certificate that will not load is refused while it can be explained,
// rather than at connect time — it is the same test mobile's (*Client).start
// applies when it builds the certificate pool.
func TestChecksTheCABundle(t *testing.T) {
	l := sample()
	l.CACertPEM = "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"
	if _, err := l.Encode(); err == nil {
		t.Fatal("encoded a profile whose CA bundle holds no certificate")
	}
	l.CACertPEM = testCAPEM
	if _, err := l.Encode(); err != nil {
		t.Fatalf("refused a real certificate: %v", err)
	}
}

// The reason a link is refused is shown to whoever tried to import it, so a
// value that fails two checks has to be reported as the one that matters. This
// is what keeps the character checks ahead of the address parse.
func TestSaysWhyRatherThanWhereItStopped(t *testing.T) {
	l := sample()
	l.Addr = "gate.example.com:443\r\n"
	_, err := l.Encode()
	if err == nil {
		t.Fatal("encoded")
	}
	if !strings.Contains(err.Error(), "control character") {
		t.Fatalf("reported as something other than what it is: %v", err)
	}
}

// A profile name is a label the user reads, not something that reaches a
// socket, so it keeps its spaces. Pinned because the check that exempts it is
// one field of a table, and a table is easy to fill in wrongly.
func TestANameMayContainSpaces(t *testing.T) {
	l := sample()
	l.Name = "Home gateway (spare)"
	raw, err := l.Encode()
	if err != nil {
		t.Fatalf("refused a name with a space: %v", err)
	}
	out, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != l.Name {
		t.Fatalf("the name changed: %q", out.Name)
	}
}
