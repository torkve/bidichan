package peer

import "encoding/json"

// Message types exchanged on the dedicated control stream. Each message is a
// single JSON object, newline-delimited. We use a discriminated-union shape
// rather than separate types per direction because both peers are equal —
// either may originate any of these.
type MsgType string

const (
	MsgOpenChannel  MsgType = "open"
	MsgOpenAck      MsgType = "open_ack"
	MsgOpenNack     MsgType = "open_nack"
	MsgCloseChannel MsgType = "close"
	MsgPing         MsgType = "ping"
	MsgPong         MsgType = "pong"
)

// ChannelKind picks the channel implementation. The control message carries
// only the kind + spec; the data plane format is determined entirely by the
// kind, so the peer that opens a channel and the peer that accepts must both
// understand the same kind.
type ChannelKind string

const (
	KindForward   ChannelKind = "forward"   // raw TCP forwarding
	KindHTTPProxy ChannelKind = "http"      // local HTTP proxy listener
	KindSocks5    ChannelKind = "socks5"    // local SOCKS5 proxy listener
	KindTUN       ChannelKind = "tun"       // packet-mode TUN device
)

// Side identifies which peer hosts the listener / proxy / tun device. From the
// CLI user's perspective "local" means the side where the CLI was invoked.
// Inside the control protocol we translate to "originator" (the peer that
// sent the open message) and "responder" (the peer receiving it).
type Side string

const (
	SideOriginator Side = "originator"
	SideResponder  Side = "responder"
)

// Envelope wraps a control message with discriminator + payload.
type Envelope struct {
	Type    MsgType         `json:"t"`
	Payload json.RawMessage `json:"p,omitempty"`
}

// OpenChannel is sent to request a new channel. ChannelID is allocated by the
// originator and is opaque to the responder; the responder must echo it back
// in the ack/nack. The responder also uses it to identify data streams that
// belong to this channel.
type OpenChannel struct {
	ChannelID uint64          `json:"id"`
	Kind      ChannelKind     `json:"kind"`
	Spec      json.RawMessage `json:"spec"`
}

// OpenAck is the affirmative response to an OpenChannel. It echoes the
// channel ID and, where applicable, returns server-allocated values such as
// the actual port that was bound when port 0 was requested.
type OpenAck struct {
	ChannelID uint64          `json:"id"`
	Info      json.RawMessage `json:"info,omitempty"`
}

// OpenNack rejects an OpenChannel. Reason is a free-form error string —
// intended for the operator, not for machine parsing.
type OpenNack struct {
	ChannelID uint64 `json:"id"`
	Reason    string `json:"reason"`
}

// CloseChannel asks the peer to tear down the named channel. Either side may
// initiate close; the receiver should release listener/socket resources and
// any in-flight streams will be reset by yamux automatically when their
// underlying readers/writers close.
type CloseChannel struct {
	ChannelID uint64 `json:"id"`
	Reason    string `json:"reason,omitempty"`
}

// ForwardSpec configures a TCP forwarding channel.
// ListenSide says which peer binds the listener; DialSide is implied to be
// the opposite peer and is where TargetAddr will be dialed.
type ForwardSpec struct {
	ListenSide Side   `json:"listen_side"`
	ListenAddr string `json:"listen_addr"` // host:port; host may be "" for all interfaces
	TargetAddr string `json:"target_addr"` // host:port the dial side will connect to
	Label      string `json:"label,omitempty"`
}

// ProxySpec configures an HTTP or SOCKS5 proxy channel. The listener runs on
// ListenSide; outbound traffic egresses on the opposite peer.
type ProxySpec struct {
	ListenSide Side   `json:"listen_side"`
	ListenAddr string `json:"listen_addr"`
	Label      string `json:"label,omitempty"`
}

// TUNSpec configures a TUN device on TUNSide. CIDR is assigned to the device
// (e.g. "10.42.0.1/24"); MTU defaults to 1400 when zero.
type TUNSpec struct {
	TUNSide Side   `json:"tun_side"`
	Name    string `json:"name,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
	Label   string `json:"label,omitempty"`
}

// AckInfoListener is returned in OpenAck when the responder is the one that
// actually bound a listener and the originator wants to know what port was
// chosen (e.g. when ListenAddr asked for :0).
type AckInfoListener struct {
	BoundAddr string `json:"bound_addr"`
}

// StreamHeader prefaces every yamux data stream so the receiver can route it
// to the right channel handler. The header is JSON-encoded and preceded by a
// little-endian uint32 length.
type StreamHeader struct {
	ChannelID uint64 `json:"id"`
	// For forwarding channels the originator may carry per-stream metadata
	// (e.g. "this stream represents an inbound conn on the reverse-forward
	// listener" or "this stream wants to dial X:Y for the proxy"). We store it
	// as raw JSON so the channel implementation interprets it.
	Meta json.RawMessage `json:"meta,omitempty"`
}

// ForwardStreamMeta is the per-stream metadata for forwarding channels.
// For a direct forward, no meta is needed — the responder dials the
// pre-configured TargetAddr.
// For proxy channels, Target indicates the address the listener-side
// resolved from the client's request.
type ForwardStreamMeta struct {
	Target string `json:"target,omitempty"`
}
