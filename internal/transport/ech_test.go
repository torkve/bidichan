package transport

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func countECH(exts []utls.TLSExtension) int {
	n := 0
	for _, ext := range exts {
		if _, ok := ext.(*utls.GREASEEncryptedClientHelloExtension); ok {
			n++
		}
	}
	return n
}

// TestClientHelloIsLatestChromeMinusECH guards two properties of the ClientHello
// the client actually sends (chromeNoECHSpec):
//
//   - It carries NO encrypted_client_hello extension (0xfe0d). Some networks
//     mishandle ECH, so we send none.
//   - It is the current Chrome spec with exactly the ECH extension removed — so
//     the hello stays current and a future regression to a stale/empty hello is
//     caught.
func TestClientHelloIsLatestChromeMinusECH(t *testing.T) {
	base, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("UTLSIdToSpec(HelloChrome_Auto): %v", err)
	}
	baseECH := countECH(base.Extensions)
	if baseECH == 0 {
		t.Skip("current HelloChrome_Auto carries no ECH extension; nothing to strip")
	}

	got, err := chromeNoECHSpec()
	if err != nil {
		t.Fatalf("chromeNoECHSpec: %v", err)
	}
	if n := countECH(got.Extensions); n != 0 {
		t.Fatalf("ClientHello still carries %d ECH extension(s); expected none", n)
	}
	if want := len(base.Extensions) - baseECH; len(got.Extensions) != want {
		t.Fatalf("stripped spec has %d extensions, want %d (latest Chrome minus %d ECH) — "+
			"only the ECH extension should be removed", len(got.Extensions), want, baseECH)
	}
}
