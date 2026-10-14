package channel

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/torkve/bidichan/internal/peer"
)

// Register attaches all channel implementations to a peer. Call this before
// peer.Start so handlers are ready when the first OpenChannel arrives.
//
// Kinds in deny stay registered — this peer may still originate them — but
// the other peer's attempts to open one of them here are refused.
func Register(p *peer.Peer, deny ...peer.ChannelKind) {
	handlers := map[peer.ChannelKind]peer.ChannelHandler{
		peer.KindForward:   &ForwardHandler{},
		peer.KindHTTPProxy: &HTTPProxyHandler{},
		peer.KindSocks5:    &Socks5ProxyHandler{},
		peer.KindTUN:       &TUNHandler{},
	}
	for _, k := range deny {
		if h, ok := handlers[k]; ok {
			handlers[k] = refusingHandler{ChannelHandler: h, kind: k}
		}
	}
	for k, h := range handlers {
		p.RegisterHandler(k, h)
	}
}

// RegisterShell attaches the interactive shell handler. allow gates whether
// this peer will *spawn* a shell when the other peer opens one; originating a
// shell on the peer is always possible once the handler is registered.
func RegisterShell(p *peer.Peer, allow bool) {
	p.RegisterHandler(peer.KindShell, &ShellHandler{allow: allow})
}

// refusingHandler wraps a kind's handler to refuse opens from the other peer
// while keeping originating (and the streams of originated channels) intact.
type refusingHandler struct {
	peer.ChannelHandler
	kind peer.ChannelKind
}

func (h refusingHandler) HandleOpen(context.Context, *peer.Peer, uint64, json.RawMessage) (json.RawMessage, peer.ChannelRunner, error) {
	return nil, nil, fmt.Errorf("%s not permitted (peer started with --deny-channel %s)", h.kind, h.kind)
}
