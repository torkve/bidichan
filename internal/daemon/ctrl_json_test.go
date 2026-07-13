package daemon

import (
	"encoding/json"
	"strings"
	"testing"
)

// newEmbedded builds a control-only daemon (no network) for exercising the
// in-process ControlJSON path used by the mobile facade.
func newEmbedded(t *testing.T) *Daemon {
	t.Helper()
	d, err := New(Config{Mode: ModeConnect, EmbedControl: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestControlJSONStatus(t *testing.T) {
	d := newEmbedded(t)
	var resp CtrlResponse
	if err := json.Unmarshal(d.ControlJSON([]byte(`{"action":"status"}`)), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	var st StatusResponse
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		t.Fatalf("unmarshal status data: %v", err)
	}
	if len(st.Peers) != 0 {
		t.Fatalf("want 0 peers, got %d", len(st.Peers))
	}
}

func TestControlJSONBadRequest(t *testing.T) {
	d := newEmbedded(t)
	var resp CtrlResponse
	_ = json.Unmarshal(d.ControlJSON([]byte(`{not json`)), &resp)
	if !strings.Contains(resp.Error, "parse request") {
		t.Fatalf("want parse error, got %q", resp.Error)
	}
}

func TestControlJSONUnknownAction(t *testing.T) {
	d := newEmbedded(t)
	var resp CtrlResponse
	_ = json.Unmarshal(d.ControlJSON([]byte(`{"action":"frobnicate"}`)), &resp)
	if !strings.Contains(resp.Error, "unknown action") {
		t.Fatalf("want unknown-action error, got %q", resp.Error)
	}
}

// TestControlJSONOpenNoPeer confirms an open action with no peer connected
// returns the same error the socket path would, proving ControlJSON reuses the
// existing dispatch rather than a divergent code path.
func TestControlJSONOpenNoPeer(t *testing.T) {
	d := newEmbedded(t)
	req := `{"action":"open_socks5","args":{"listen_side":"local","listen_addr":"127.0.0.1:1080"}}`
	var resp CtrlResponse
	_ = json.Unmarshal(d.ControlJSON([]byte(req)), &resp)
	if !strings.Contains(resp.Error, "no active peer") {
		t.Fatalf("want no-active-peer error, got %q", resp.Error)
	}
}
