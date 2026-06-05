package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/torkve/bidichan/internal/channel"
	"github.com/torkve/bidichan/internal/peer"
	"github.com/torkve/bidichan/internal/transport"
)

// The benchmarks below cover the steady-state data plane of every channel
// kind. They isolate the transport-+-yamux-+-channel-handler pipeline by
// running fully on loopback: the bidichan client and server live inside the
// same process, the TLS layer is real (uTLS Chrome on the client + stdlib
// server), and the channel target is a tight read-and-discard sink.
//
// What each metric means:
//
//   - "MB/s": throughput as reported by b.SetBytes. Each iteration writes
//     one block; b.N iterations land in the sink. The framework times
//     enough iterations to fill ~1s of wall clock.
//   - "B/op": bytes allocated per iteration (heap, from runtime).
//   - "allocs/op": distinct allocations per iteration.
//   - "cpu_ms/MB": process CPU time spent (user+sys, via Getrusage) per
//     megabyte transferred. Lower is better.
//
// TUN cannot be benchmarked end-to-end here — it needs CAP_NET_ADMIN and
// a real /dev/net/tun. BenchmarkTUNFraming covers the per-packet framing
// overhead (length-prefix + read/write), which is the only bidichan-side
// cost that scales with packet rate.

func benchPair(b *testing.B, hostname string) (*peer.Peer, *peer.Peer, func()) {
	b.Helper()
	psk := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
	}
	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(io.Discard, "", 0)

	lis, err := transport.Listen(ctx, "127.0.0.1:0", transport.ServerConfig{
		Hostname: hostname,
		PSK:      psk,
		Logger:   logger,
	})
	if err != nil {
		cancel()
		b.Fatalf("Listen: %v", err)
	}

	serverCh := make(chan *peer.Peer, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := lis.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		p, err := peer.NewPeer(peer.RoleServer, c, "srv", logger)
		if err != nil {
			errCh <- err
			return
		}
		channel.Register(p)
		if err := p.Start(ctx); err != nil {
			errCh <- err
			return
		}
		serverCh <- p
	}()

	cliConn, err := transport.Dial(ctx, lis.Addr().String(), transport.ClientConfig{
		Hostname: hostname,
		PSK:      psk,
		RootCAs:  rootsFor(b, lis),
	})
	if err != nil {
		cancel()
		_ = lis.Close()
		b.Fatalf("Dial: %v", err)
	}
	cliPeer, err := peer.NewPeer(peer.RoleClient, cliConn, "cli", logger)
	if err != nil {
		cancel()
		_ = lis.Close()
		b.Fatalf("NewPeer client: %v", err)
	}
	channel.Register(cliPeer)
	if err := cliPeer.Start(ctx); err != nil {
		cancel()
		_ = lis.Close()
		b.Fatalf("Start client: %v", err)
	}

	var srvPeer *peer.Peer
	select {
	case srvPeer = <-serverCh:
	case err := <-errCh:
		cancel()
		_ = lis.Close()
		b.Fatalf("server accept: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		_ = lis.Close()
		b.Fatal("timeout waiting for server peer")
	}

	teardown := func() {
		_ = cliPeer.Close()
		_ = srvPeer.Close()
		cancel()
		_ = lis.Close()
	}
	return cliPeer, srvPeer, teardown
}

// startSink stands up a TCP listener that reads bytes and discards them as
// fast as it can. Returns the address the bench can target.
func startSink(b *testing.B) (string, func()) {
	b.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return lis.Addr().String(), func() { _ = lis.Close() }
}

// dialThroughProxy returns a net.Conn through whichever channel kind we're
// benchmarking. For forward channels the local listener is already a TCP
// listener targeting the sink; for proxy channels we do the CONNECT
// handshake here so the bench's hot loop is pure write().
func dialThroughProxy(b *testing.B, kind peer.ChannelKind, frontAddr, target string) net.Conn {
	b.Helper()
	conn, err := net.Dial("tcp", frontAddr)
	if err != nil {
		b.Fatalf("dial frontend: %v", err)
	}
	switch kind {
	case peer.KindForward:
		// frontend already targets the sink — no extra handshake.
		return conn
	case peer.KindHTTPProxy:
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
			b.Fatal(err)
		}
		br := bufio.NewReader(conn)
		status, err := br.ReadString('\n')
		if err != nil {
			b.Fatal(err)
		}
		if !strings.Contains(status, " 200 ") {
			b.Fatalf("CONNECT failed: %q", status)
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				b.Fatal(err)
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		return conn
	case peer.KindSocks5:
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			b.Fatal(err)
		}
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			b.Fatal(err)
		}
		if hdr[0] != 0x05 || hdr[1] != 0x00 {
			b.Fatalf("bad SOCKS5 greeting: %v", hdr)
		}
		host, portStr, _ := net.SplitHostPort(target)
		ip := net.ParseIP(host).To4()
		port, _ := strconv.Atoi(portStr)
		req := []byte{0x05, 0x01, 0x00, 0x01}
		req = append(req, ip...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], uint16(port))
		req = append(req, pb[:]...)
		if _, err := conn.Write(req); err != nil {
			b.Fatal(err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(conn, reply); err != nil {
			b.Fatal(err)
		}
		if reply[0] != 0x05 || reply[1] != 0x00 {
			b.Fatalf("CONNECT rejected: %v", reply)
		}
		return conn
	}
	b.Fatalf("unknown kind %s", kind)
	return nil
}

// findListener pulls the bound listen address out of the originator's
// channel snapshot. Returns "" if the channel hasn't bound yet.
func findListener(p *peer.Peer, k peer.ChannelKind) string {
	for _, ch := range p.Snapshot() {
		if ch.Kind != k {
			continue
		}
		if addr := extractListenAddr(ch.Description); addr != "" {
			return addr
		}
	}
	return ""
}

// rusageDelta records process-level CPU time and reports cpu_ms/MB at the
// end of a bench run. The delta is process-wide — Go's test runner doesn't
// expose per-bench CPU — but since each bench in this file follows the same
// setup-then-tight-loop pattern, the delta is a fair proxy for the cost of
// pushing bytes through that specific channel.
type rusageDelta struct {
	before syscall.Rusage
}

func startRusage() rusageDelta {
	var r rusageDelta
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &r.before)
	return r
}

func (r rusageDelta) report(b *testing.B, blockSize int) {
	var after syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		return
	}
	uDelta := timevalDur(after.Utime) - timevalDur(r.before.Utime)
	sDelta := timevalDur(after.Stime) - timevalDur(r.before.Stime)
	cpuMs := float64((uDelta + sDelta) / time.Millisecond)
	bytes := float64(int64(blockSize) * int64(b.N))
	mb := bytes / (1 << 20)
	if mb > 0 {
		b.ReportMetric(cpuMs/mb, "cpu_ms/MB")
	}
	// Peak RSS (maxrss is in KB on Linux) — informational; reported as MB.
	b.ReportMetric(float64(after.Maxrss)/1024.0, "peak_rss_MB")
}

func timevalDur(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}

func benchChannelWrite(b *testing.B, kind peer.ChannelKind, blockSize int) {
	cli, _, teardown := benchPair(b, "example.test")
	defer teardown()

	sinkAddr, stopSink := startSink(b)
	defer stopSink()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var spec any
	switch kind {
	case peer.KindForward:
		spec = peer.ForwardSpec{
			ListenSide: peer.SideOriginator,
			ListenAddr: "127.0.0.1:0",
			TargetAddr: sinkAddr,
		}
	case peer.KindHTTPProxy, peer.KindSocks5:
		spec = peer.ProxySpec{
			ListenSide: peer.SideOriginator,
			ListenAddr: "127.0.0.1:0",
		}
	default:
		b.Fatalf("unsupported kind %s", kind)
	}
	if _, err := cli.OpenChannel(ctx, kind, spec); err != nil {
		b.Fatalf("OpenChannel: %v", err)
	}

	var frontAddr string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if frontAddr = findListener(cli, kind); frontAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if frontAddr == "" {
		b.Fatal("listener never bound")
	}

	conn := dialThroughProxy(b, kind, frontAddr, sinkAddr)
	defer conn.Close()

	// Pre-fill a random buffer so the loop doesn't repeatedly hit the same
	// runs of bytes, which can confuse the kernel's TCP path.
	block := make([]byte, blockSize)
	_, _ = rand.Read(block)

	// Settle: do one write+drain to make sure all stream setup is paid
	// for before the timer starts.
	if _, err := conn.Write(block); err != nil {
		b.Fatalf("warmup write: %v", err)
	}

	runtime.GC()
	ru := startRusage()
	b.SetBytes(int64(blockSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(block); err != nil {
			b.Fatalf("write iter %d: %v", i, err)
		}
	}
	b.StopTimer()
	ru.report(b, blockSize)
}

func benchChannelEcho(b *testing.B, kind peer.ChannelKind, payloadSize int) {
	cli, _, teardown := benchPair(b, "example.test")
	defer teardown()

	echoAddr, stopEcho := startEchoB(b)
	defer stopEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var spec any
	switch kind {
	case peer.KindForward:
		spec = peer.ForwardSpec{
			ListenSide: peer.SideOriginator,
			ListenAddr: "127.0.0.1:0",
			TargetAddr: echoAddr,
		}
	case peer.KindHTTPProxy, peer.KindSocks5:
		spec = peer.ProxySpec{
			ListenSide: peer.SideOriginator,
			ListenAddr: "127.0.0.1:0",
		}
	default:
		b.Fatalf("unsupported kind %s", kind)
	}
	if _, err := cli.OpenChannel(ctx, kind, spec); err != nil {
		b.Fatalf("OpenChannel: %v", err)
	}
	var frontAddr string
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if frontAddr = findListener(cli, kind); frontAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if frontAddr == "" {
		b.Fatal("listener never bound")
	}
	conn := dialThroughProxy(b, kind, frontAddr, echoAddr)
	defer conn.Close()

	out := make([]byte, payloadSize)
	in := make([]byte, payloadSize)
	_, _ = rand.Read(out)

	// Warmup round-trip.
	if _, err := conn.Write(out); err != nil {
		b.Fatal(err)
	}
	if _, err := io.ReadFull(conn, in); err != nil {
		b.Fatal(err)
	}

	runtime.GC()
	ru := startRusage()
	b.SetBytes(int64(payloadSize * 2)) // round-trip = both directions
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(out); err != nil {
			b.Fatalf("write iter %d: %v", i, err)
		}
		if _, err := io.ReadFull(conn, in); err != nil {
			b.Fatalf("read iter %d: %v", i, err)
		}
	}
	b.StopTimer()
	ru.report(b, payloadSize*2)
}

func startEchoB(b *testing.B) (string, func()) {
	b.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return lis.Addr().String(), func() { _ = lis.Close() }
}

// --- Throughput benchmarks (one-way write to /dev/null sink). ---

func BenchmarkForwardThroughput64K(b *testing.B)  { benchChannelWrite(b, peer.KindForward, 64<<10) }
func BenchmarkForwardThroughput256K(b *testing.B) { benchChannelWrite(b, peer.KindForward, 256<<10) }
func BenchmarkHTTPThroughput64K(b *testing.B)     { benchChannelWrite(b, peer.KindHTTPProxy, 64<<10) }
func BenchmarkHTTPThroughput256K(b *testing.B)    { benchChannelWrite(b, peer.KindHTTPProxy, 256<<10) }
func BenchmarkSOCKS5Throughput64K(b *testing.B)   { benchChannelWrite(b, peer.KindSocks5, 64<<10) }
func BenchmarkSOCKS5Throughput256K(b *testing.B)  { benchChannelWrite(b, peer.KindSocks5, 256<<10) }

// --- Round-trip latency / small-payload echo. ---

func BenchmarkForwardEcho16B(b *testing.B) { benchChannelEcho(b, peer.KindForward, 16) }
func BenchmarkHTTPEcho16B(b *testing.B)    { benchChannelEcho(b, peer.KindHTTPProxy, 16) }
func BenchmarkSOCKS5Echo16B(b *testing.B)  { benchChannelEcho(b, peer.KindSocks5, 16) }

// --- TUN framing-only microbenchmark. ---
//
// We can't open a real TUN device in the bench (CAP_NET_ADMIN + /dev/net/tun).
// What we CAN measure is the framing cost — length-prefix encode/decode +
// the read/write round-trip through a yamux stream. This is the only
// bidichan-side overhead that scales with packet rate; the rest is the
// kernel doing the same work it would for any virtual NIC.

func BenchmarkTUNFraming1500B(b *testing.B) { benchTUNFraming(b, 1500) }
func BenchmarkTUNFraming9000B(b *testing.B) { benchTUNFraming(b, 9000) }

func benchTUNFraming(b *testing.B, packetSize int) {
	cli, _, teardown := benchPair(b, "example.test")
	defer teardown()

	// Open a raw yamux stream by piggy-backing on a forward channel: the
	// channel kind doesn't matter for the framing layer — we read and write
	// length-prefixed packets ourselves on the stream and measure that.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sinkAddr, stopSink := startSink(b)
	defer stopSink()

	if _, err := cli.OpenChannel(ctx, peer.KindForward, peer.ForwardSpec{
		ListenSide: peer.SideOriginator,
		ListenAddr: "127.0.0.1:0",
		TargetAddr: sinkAddr,
	}); err != nil {
		b.Fatal(err)
	}
	var frontAddr string
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if frontAddr = findListener(cli, peer.KindForward); frontAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if frontAddr == "" {
		b.Fatal("listener never bound")
	}
	conn, err := net.Dial("tcp", frontAddr)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	// Framing emulates what tun.go does: uint16 LE length prefix + payload.
	payload := make([]byte, packetSize)
	_, _ = rand.Read(payload)
	hdr := make([]byte, 2)
	binary.LittleEndian.PutUint16(hdr, uint16(packetSize))

	// Warmup.
	if _, err := conn.Write(hdr); err != nil {
		b.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		b.Fatal(err)
	}

	runtime.GC()
	ru := startRusage()
	b.SetBytes(int64(packetSize + 2))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(hdr); err != nil {
			b.Fatalf("write hdr: %v", err)
		}
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("write payload: %v", err)
		}
	}
	b.StopTimer()
	ru.report(b, packetSize+2)
}
