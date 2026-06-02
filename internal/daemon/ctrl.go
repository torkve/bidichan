package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/torkve/bidichan/internal/peer"
)

// CtrlRequest is the wire format on the daemon control socket. Action is one
// of the strings below; Args is action-specific JSON.
type CtrlRequest struct {
	Action string          `json:"action"`
	Args   json.RawMessage `json:"args,omitempty"`
}

// CtrlResponse is what the daemon sends back. Either Error is set OR Data is.
type CtrlResponse struct {
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

const (
	ActionStatus       = "status"
	ActionOpenForward  = "open_forward"
	ActionOpenHTTP     = "open_http"
	ActionOpenSocks5   = "open_socks5"
	ActionOpenTUN      = "open_tun"
	ActionClose        = "close_channel"
	ActionShutdown     = "shutdown"
)

// StatusResponse summarises every peer and its open channels.
type StatusResponse struct {
	Peers []PeerStatus `json:"peers"`
}

// PeerStatus describes one peer for the CLI.
type PeerStatus struct {
	ID         string                 `json:"id"`
	Remote     string                 `json:"remote"`
	Local      string                 `json:"local"`
	StartedAt  time.Time              `json:"started_at"`
	Mode       string                 `json:"mode"`
	Channels   []peer.ChannelSnapshot `json:"channels"`
}

// OpenForwardArgs / OpenProxyArgs / OpenTUNArgs / CloseArgs are the
// per-action payloads. They're tiny so we inline them here rather than
// scatter them across a /api/ directory.
type OpenForwardArgs struct {
	PeerID     string `json:"peer_id"`
	ListenSide string `json:"listen_side"` // "local" or "remote"
	ListenAddr string `json:"listen_addr"`
	TargetAddr string `json:"target_addr"`
	Label      string `json:"label,omitempty"`
}

type OpenProxyArgs struct {
	PeerID     string `json:"peer_id"`
	ListenSide string `json:"listen_side"` // "local" or "remote"
	ListenAddr string `json:"listen_addr"`
	Label      string `json:"label,omitempty"`
}

type OpenTUNArgs struct {
	PeerID  string `json:"peer_id"`
	TUNSide string `json:"tun_side"` // "local" or "remote"
	Name    string `json:"name,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
	Label   string `json:"label,omitempty"`
}

type CloseArgs struct {
	PeerID    string `json:"peer_id"`
	ChannelID uint64 `json:"channel_id"`
}

// OpenResponse echoes the new channel id back to the CLI.
type OpenResponse struct {
	ChannelID uint64          `json:"channel_id"`
	Info      json.RawMessage `json:"info,omitempty"`
}

func (d *Daemon) startCtrl() error {
	if err := os.MkdirAll(filepath.Dir(d.cfg.ControlSocket), 0o700); err != nil {
		return err
	}
	_ = os.Remove(d.cfg.ControlSocket) // remove stale
	lis, err := net.Listen("unix", d.cfg.ControlSocket)
	if err != nil {
		return err
	}
	if err := os.Chmod(d.cfg.ControlSocket, 0o600); err != nil {
		_ = lis.Close()
		return err
	}
	d.ctrlLis = lis
	d.ctrlDir = filepath.Dir(d.cfg.ControlSocket)
	go d.acceptCtrl()
	return nil
}

func (d *Daemon) acceptCtrl() {
	for {
		c, err := d.ctrlLis.Accept()
		if err != nil {
			return
		}
		go d.handleCtrl(c)
	}
}

func (d *Daemon) handleCtrl(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		var req CtrlRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeCtrlErr(bw, fmt.Errorf("parse request: %w", err))
			return
		}
		resp := d.dispatchCtrl(req)
		b, _ := json.Marshal(resp)
		_, _ = bw.Write(b)
		_, _ = bw.Write([]byte("\n"))
		_ = bw.Flush()
		if req.Action == ActionShutdown {
			go func() {
				time.Sleep(100 * time.Millisecond)
				_ = d.Close()
			}()
			return
		}
	}
}

func writeCtrlErr(w io.Writer, err error) {
	b, _ := json.Marshal(CtrlResponse{Error: err.Error()})
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

func (d *Daemon) dispatchCtrl(req CtrlRequest) CtrlResponse {
	switch req.Action {
	case ActionStatus:
		return d.ctrlStatus()
	case ActionOpenForward:
		var args OpenForwardArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return ctrlErr(err)
		}
		return d.ctrlOpenForward(args)
	case ActionOpenHTTP:
		var args OpenProxyArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return ctrlErr(err)
		}
		return d.ctrlOpenProxy(args, peer.KindHTTPProxy)
	case ActionOpenSocks5:
		var args OpenProxyArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return ctrlErr(err)
		}
		return d.ctrlOpenProxy(args, peer.KindSocks5)
	case ActionOpenTUN:
		var args OpenTUNArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return ctrlErr(err)
		}
		return d.ctrlOpenTUN(args)
	case ActionClose:
		var args CloseArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return ctrlErr(err)
		}
		return d.ctrlCloseChannel(args)
	case ActionShutdown:
		return CtrlResponse{Data: json.RawMessage(`{"ok":true}`)}
	default:
		return ctrlErr(fmt.Errorf("unknown action %q", req.Action))
	}
}

func ctrlErr(err error) CtrlResponse {
	return CtrlResponse{Error: err.Error()}
}

func ctrlOK(v any) CtrlResponse {
	b, err := json.Marshal(v)
	if err != nil {
		return ctrlErr(err)
	}
	return CtrlResponse{Data: b}
}

func (d *Daemon) ctrlStatus() CtrlResponse {
	out := StatusResponse{}
	for _, p := range d.Peers() {
		mode := "server"
		if d.cfg.Mode == ModeConnect {
			mode = "client"
		}
		out.Peers = append(out.Peers, PeerStatus{
			ID:        p.ID(),
			Remote:    p.RemoteAddr(),
			Local:     p.LocalAddr(),
			StartedAt: p.StartedAt(),
			Mode:      mode,
			Channels:  p.Snapshot(),
		})
	}
	return ctrlOK(out)
}

func (d *Daemon) requirePeer(id string) (*peer.Peer, error) {
	if id == "" {
		// If only one peer exists, use it.
		ps := d.Peers()
		if len(ps) == 1 {
			return ps[0], nil
		}
		if len(ps) == 0 {
			return nil, errors.New("no active peer connections")
		}
		return nil, fmt.Errorf("multiple peers connected; specify --peer (have %d)", len(ps))
	}
	if p := d.PeerByID(id); p != nil {
		return p, nil
	}
	// Accept a prefix match for convenience.
	var match *peer.Peer
	for _, p := range d.Peers() {
		if strings.HasPrefix(p.ID(), id) {
			if match != nil {
				return nil, fmt.Errorf("peer prefix %q is ambiguous", id)
			}
			match = p
		}
	}
	if match != nil {
		return match, nil
	}
	return nil, fmt.Errorf("no peer matches %q", id)
}

func sideFromString(s string) (peer.Side, error) {
	switch strings.ToLower(s) {
	case "local":
		return peer.SideOriginator, nil
	case "remote":
		return peer.SideResponder, nil
	}
	return "", fmt.Errorf("invalid side %q (want local|remote)", s)
}

func (d *Daemon) ctrlOpenForward(args OpenForwardArgs) CtrlResponse {
	p, err := d.requirePeer(args.PeerID)
	if err != nil {
		return ctrlErr(err)
	}
	side, err := sideFromString(args.ListenSide)
	if err != nil {
		return ctrlErr(err)
	}
	spec := peer.ForwardSpec{
		ListenSide: side,
		ListenAddr: args.ListenAddr,
		TargetAddr: args.TargetAddr,
		Label:      args.Label,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id, err := p.OpenChannel(ctx, peer.KindForward, spec)
	if err != nil {
		return ctrlErr(err)
	}
	return ctrlOK(OpenResponse{ChannelID: id})
}

func (d *Daemon) ctrlOpenProxy(args OpenProxyArgs, kind peer.ChannelKind) CtrlResponse {
	p, err := d.requirePeer(args.PeerID)
	if err != nil {
		return ctrlErr(err)
	}
	side, err := sideFromString(args.ListenSide)
	if err != nil {
		return ctrlErr(err)
	}
	spec := peer.ProxySpec{
		ListenSide: side,
		ListenAddr: args.ListenAddr,
		Label:      args.Label,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id, err := p.OpenChannel(ctx, kind, spec)
	if err != nil {
		return ctrlErr(err)
	}
	return ctrlOK(OpenResponse{ChannelID: id})
}

func (d *Daemon) ctrlOpenTUN(args OpenTUNArgs) CtrlResponse {
	p, err := d.requirePeer(args.PeerID)
	if err != nil {
		return ctrlErr(err)
	}
	side, err := sideFromString(args.TUNSide)
	if err != nil {
		return ctrlErr(err)
	}
	spec := peer.TUNSpec{
		TUNSide: side,
		Name:    args.Name,
		CIDR:    args.CIDR,
		MTU:     args.MTU,
		Label:   args.Label,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id, err := p.OpenChannel(ctx, peer.KindTUN, spec)
	if err != nil {
		return ctrlErr(err)
	}
	return ctrlOK(OpenResponse{ChannelID: id})
}

func (d *Daemon) ctrlCloseChannel(args CloseArgs) CtrlResponse {
	p, err := d.requirePeer(args.PeerID)
	if err != nil {
		return ctrlErr(err)
	}
	if err := p.CloseChannelByID(args.ChannelID, "closed by CLI"); err != nil {
		return ctrlErr(err)
	}
	return ctrlOK(map[string]bool{"ok": true})
}

// FormatBoundAddr extracts the BoundAddr field from an AckInfoListener-style
// json blob, for nicer CLI output. Returns "" if the blob can't be parsed.
func FormatBoundAddr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var info struct {
		BoundAddr string `json:"bound_addr"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return ""
	}
	return info.BoundAddr
}

// Keep strconv referenced for future formatting helpers.
var _ = strconv.Itoa
