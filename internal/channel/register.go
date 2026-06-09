package channel

import "github.com/torkve/bidichan/internal/peer"

// Register attaches all channel implementations to a peer. Call this before
// peer.Start so handlers are ready when the first OpenChannel arrives.
func Register(p *peer.Peer) {
	p.RegisterHandler(peer.KindForward, &ForwardHandler{})
	p.RegisterHandler(peer.KindHTTPProxy, &HTTPProxyHandler{})
	p.RegisterHandler(peer.KindSocks5, &Socks5ProxyHandler{})
	p.RegisterHandler(peer.KindTUN, &TUNHandler{})
}

// RegisterShell attaches the interactive shell handler. allow gates whether
// this peer will *spawn* a shell when the other peer opens one; originating a
// shell on the peer is always possible once the handler is registered.
func RegisterShell(p *peer.Peer, allow bool) {
	p.RegisterHandler(peer.KindShell, &ShellHandler{allow: allow})
}
