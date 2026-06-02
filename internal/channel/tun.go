package channel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"sync"

	"github.com/songgao/water"
	"github.com/torkve/bidichan/internal/peer"
)

// TUNHandler creates an L3 TUN device on whichever side the spec selects and
// frames packets across a single dedicated yamux stream. Frames are
// length-prefixed (uint16 LE) so the stream remains a clean bytestream.
//
// The peer that does NOT host the TUN device still participates as the
// packet egress: it must run with appropriate privileges if its own TUN-side
// configuration involves binding addresses, but the simpler model is:
//   - Side A creates the TUN, assigns 10.42.0.1/24
//   - Side B forwards packets received on the stream into its own
//     network stack via its own TUN (or simply sends them onward via its
//     own routes — but we keep the model symmetric and require a TUN on
//     each side that wants to terminate the link)
//
// To keep the code straightforward and the privilege model honest, we
// require a TUN device on the side TUNSide names and have the *opposite*
// side just relay the bytestream onto another TUN of its own using the
// same spec mirrored. In the common case the operator runs `bidichan
// channel open tun` on both sides with matching CIDRs so each peer terminates
// the link locally.
//
// For v1 we implement the simpler "one TUN device, one stream" model:
//   - Whichever side TUNSide points to creates the device and asserts the
//     CIDR + MTU.
//   - The other side just opens a stream and reads/writes raw packets
//     against its own local TUN device that it also created from the same
//     CLI invocation.
//
// In other words, TUN is symmetric — both peers must `channel open tun` to
// form a point-to-point L3 link. We keep that constraint explicit in the
// channel descriptor so the operator knows.
type TUNHandler struct{}

func (h *TUNHandler) HandleOpen(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage) (json.RawMessage, peer.ChannelRunner, error) {
	return setupTUN(ctx, p, chID, specRaw, false)
}

func (h *TUNHandler) HandleOriginate(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage, _ json.RawMessage) (peer.ChannelRunner, error) {
	_, r, err := setupTUN(ctx, p, chID, specRaw, true)
	return r, err
}

func (h *TUNHandler) HandleStream(ctx context.Context, p *peer.Peer, runner peer.ChannelRunner, stream net.Conn, _ json.RawMessage) error {
	tr := runner.(*tunRunner)
	return tr.attachStream(stream)
}

type tunRunner struct {
	spec    peer.TUNSpec
	ifce    *water.Interface
	stream  net.Conn
	mu      sync.Mutex
	closed  chan struct{}
	closeOn sync.Once
}

func (r *tunRunner) Close() error {
	r.closeOn.Do(func() {
		close(r.closed)
		if r.ifce != nil {
			_ = r.ifce.Close()
		}
		if r.stream != nil {
			_ = r.stream.Close()
		}
	})
	return nil
}

func (r *tunRunner) Description() string {
	name := "?"
	if r.ifce != nil {
		name = r.ifce.Name()
	}
	return fmt.Sprintf("tun dev=%s cidr=%s mtu=%d", name, r.spec.CIDR, r.effMTU())
}

func (r *tunRunner) effMTU() int {
	if r.spec.MTU > 0 {
		return r.spec.MTU
	}
	return 1400
}

func setupTUN(ctx context.Context, p *peer.Peer, chID uint64, specRaw json.RawMessage, originator bool) (json.RawMessage, peer.ChannelRunner, error) {
	var spec peer.TUNSpec
	if err := json.Unmarshal(specRaw, &spec); err != nil {
		return nil, nil, fmt.Errorf("tun spec: %w", err)
	}
	// Both sides create a TUN device. TUNSide indicates which side is the
	// "primary" for naming/CIDR purposes; the opposite side mirrors with a
	// best-effort default device name.
	cfg := water.Config{DeviceType: water.TUN}
	if runtime.GOOS == "linux" && spec.Name != "" {
		applyLinuxName(&cfg, spec.Name)
	}
	ifce, err := water.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("create tun: %w", err)
	}
	r := &tunRunner{
		spec:   spec,
		ifce:   ifce,
		closed: make(chan struct{}),
	}

	if spec.CIDR != "" {
		if err := configureInterface(ifce.Name(), spec.CIDR, r.effMTU()); err != nil {
			_ = ifce.Close()
			return nil, nil, fmt.Errorf("configure tun %s: %w", ifce.Name(), err)
		}
	}

	if originator {
		// The originator opens the dedicated data stream right after the ack
		// is received. We do that in HandleOriginate via the peer's stream
		// opener — but we need the chID, so we capture it here and launch.
		go r.openAndPump(ctx, p, chID)
	}
	// Responder waits for the stream to come in via HandleStream.

	info, _ := json.Marshal(map[string]string{"device": ifce.Name()})
	return info, r, nil
}

func (r *tunRunner) openAndPump(ctx context.Context, p *peer.Peer, chID uint64) {
	s, err := p.OpenStream(chID, nil)
	if err != nil {
		_ = r.Close()
		return
	}
	_ = r.attachStream(s)
}

func (r *tunRunner) attachStream(s net.Conn) error {
	r.mu.Lock()
	if r.stream != nil {
		r.mu.Unlock()
		_ = s.Close()
		return errors.New("tun: stream already attached")
	}
	r.stream = s
	r.mu.Unlock()

	mtu := r.effMTU()
	errCh := make(chan error, 2)
	// TUN -> stream
	go func() {
		buf := make([]byte, mtu+4)
		for {
			n, err := r.ifce.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if n <= 0 {
				continue
			}
			var hdr [2]byte
			binary.LittleEndian.PutUint16(hdr[:], uint16(n))
			if _, err := s.Write(hdr[:]); err != nil {
				errCh <- err
				return
			}
			if _, err := s.Write(buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()
	// stream -> TUN
	go func() {
		hdr := make([]byte, 2)
		buf := make([]byte, mtu+64)
		for {
			if _, err := io.ReadFull(s, hdr); err != nil {
				errCh <- err
				return
			}
			n := binary.LittleEndian.Uint16(hdr)
			if int(n) > len(buf) {
				buf = make([]byte, int(n)+64)
			}
			if _, err := io.ReadFull(s, buf[:n]); err != nil {
				errCh <- err
				return
			}
			if _, err := r.ifce.Write(buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()
	<-errCh
	_ = r.Close()
	return nil
}

// configureInterface assigns an IP/CIDR and brings up the device using `ip`
// on Linux. On other OSes this is a no-op and the operator must configure
// the device out of band.
func configureInterface(dev, cidr string, mtu int) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	cmds := [][]string{
		{"ip", "link", "set", "dev", dev, "mtu", fmt.Sprintf("%d", mtu)},
		{"ip", "addr", "add", cidr, "dev", dev},
		{"ip", "link", "set", "dev", dev, "up"},
	}
	for _, c := range cmds {
		out, err := exec.Command(c[0], c[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %w: %s", c, err, string(out))
		}
	}
	return nil
}
