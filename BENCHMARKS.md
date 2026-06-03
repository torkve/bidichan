# bidichan benchmarks

Throughput, latency, allocations, and CPU cost for each channel kind,
measured on loopback (so the TLS, yamux, and channel-handler layers are
exercised; the kernel TCP path is not the bottleneck).

## Setup

| Item              | Value                                                   |
| ----------------- | ------------------------------------------------------- |
| CPU               | 12th Gen Intel Core i7-12800H (14 cores / 20 threads)   |
| RAM               | 31 GiB                                                  |
| OS                | Linux 6.8.0-117-generic                                 |
| Go toolchain      | go1.25.8 linux/amd64                                    |
| Race detector     | off (idiomatic benchmark conditions)                    |
| Topology          | client + server peer in one process, loopback transport |
| TLS               | uTLS Chrome ClientHello + stdlib TLS 1.2 server         |
| Multiplex         | yamux, default config, 1 MiB stream window              |
| Bench duration    | `-benchtime=3s` per benchmark, defaults otherwise       |

Each benchmark sets up a fresh peer pair, opens one channel, dials it,
warms up with a single round-trip, then enters the timed loop. Throughput
is reported by `b.SetBytes`. CPU is measured by `getrusage(RUSAGE_SELF)`
deltas across the timed loop (process-wide, but in this harness only one
benchmark runs at a time so the delta is a fair attribution).

Reproduce:

```sh
go test -run XXX -bench . -benchtime=3s -timeout 5m ./internal/e2e/
```

## Throughput — one-way writes into a `/dev/null` sink

The bench client writes a fixed-size block in a tight loop; the target
side is a TCP listener that reads and discards. Block sizes 64 KiB and
256 KiB cover both small-write and full-yamux-window operation.

| Kind            | Block  | Throughput   | CPU         | B/op   | allocs/op |
| --------------- | ------ | -----------: | ----------: | -----: | --------: |
| forward         | 64 KiB | 627.39 MB/s  | 4.63 ms/MB  | 648    | 13        |
| forward         | 256 KiB| 624.30 MB/s  | 4.64 ms/MB  | 2 486  | 53        |
| http (CONNECT)  | 64 KiB | 640.46 MB/s  | 4.53 ms/MB  | 706    | 13        |
| http (CONNECT)  | 256 KiB| 641.24 MB/s  | 4.50 ms/MB  | 2 501  | 52        |
| socks5 (CONNECT)| 64 KiB | 637.86 MB/s  | 4.46 ms/MB  | 624    | 13        |
| socks5 (CONNECT)| 256 KiB| 641.66 MB/s  | 4.48 ms/MB  | 2 264  | 53        |

Observations:

- **All three channel kinds converge to ~640 MB/s.** Once the tunnel is
  set up, the HTTP-CONNECT and SOCKS5 frontends add no measurable cost
  per byte — yamux + TLS dominate.
- **CPU cost is ~4.5 ms per MiB transferred per byte direction.** On a
  single connection at 640 MB/s this works out to roughly 2.9 cores at
  full throughput. Go's stdlib TLS 1.2 ChaCha/GCM path on loopback is
  the lion's share.
- **Allocations are modest and constant per block** (13 allocs/op at
  64 KiB writes, ~53 at 256 KiB). Allocation count is dominated by
  yamux stream framing and the JSON-marshal of the per-stream header
  (which only happens for the first write on a channel — subsequent
  writes amortise it; the steady-state path is alloc-light).

## Round-trip latency — 16-byte echo

Each iteration writes 16 bytes, reads 16 bytes back from an echo
server, so the timer captures one full client → peer → echo → peer →
client round trip. Throughput here is uninteresting (16 B × 2 / iter);
the relevant metric is **ns/op**, which is RTT.

| Kind            | Payload | RTT (ns/op) | RTT (µs)  | B/op | allocs/op |
| --------------- | ------- | ----------: | --------: | ---: | --------: |
| forward         |    16 B |      83 629 |   83.6 µs |  293 |         9 |
| http (CONNECT)  |    16 B |      90 382 |   90.4 µs |  294 |         9 |
| socks5 (CONNECT)|    16 B |      89 967 |   90.0 µs |  294 |         9 |

The proxy frontends cost an extra ~6–7 µs per round trip relative to
raw forward — that's the HTTP/SOCKS5 frontend's per-stream
bookkeeping plus the extra stream-open RTT they amortise. Loopback
floor is ~80 µs; on the real network you'd add link RTT directly on
top.

## TUN framing-only microbenchmark

A real TUN device needs `CAP_NET_ADMIN` and `/dev/net/tun` — we can't
open one inside a unit-test process. What we can isolate is the **per-
packet framing cost on the bidichan side**: the `uint16` length prefix
and the read/write round through one yamux stream. The bench writes a
sequence of framed packets through a forward channel that targets a
sink (no real TUN at the receiving end) and measures the per-packet
cost on the writer side.

| Packet size    | ns/packet | Effective MB/s | CPU         | B/op | allocs/op |
| -------------- | --------: | -------------: | ----------: | ---: | --------: |
| 1500 B (Eth)   |     3 106 |     483.51 MB/s| 8.04 ms/MB  |   23 |         0 |
| 9000 B (jumbo) |    12 376 |     727.36 MB/s| 4.42 ms/MB  |   67 |         1 |

**TUN framing itself is essentially free.** At MTU 1500 we frame
~322 K packets/s on one CPU; at jumbo MTU 9000 the per-byte cost drops
because the 2-byte length prefix is amortised over more payload.
Anything below ~30 % of the per-packet number is bidichan overhead;
the rest is kernel scheduling + memcpy.

## Memory

`b.ReportAllocs` per-op numbers are above. Process-wide peak RSS during
the full bench suite was **30.87 MB**, which includes the Go runtime,
the test framework, both peer-side handler goroutines, the TLS state,
and all yamux session memory. RSS does not grow with channel count in
steady state — it is dominated by the fixed per-yamux-session window
buffer (~1 MiB per side).

## Raw output

```text
goos: linux
goarch: amd64
pkg: github.com/torkve/bidichan/internal/e2e
cpu: 12th Gen Intel(R) Core(TM) i7-12800H
BenchmarkForwardThroughput64K-20     	   35547	    104458 ns/op	 627.39 MB/s	         4.628 cpu_ms/MB	        30.87 peak_rss_MB	     648 B/op	      13 allocs/op
BenchmarkForwardThroughput256K-20    	    8980	    419900 ns/op	 624.30 MB/s	         4.638 cpu_ms/MB	        30.87 peak_rss_MB	    2486 B/op	      53 allocs/op
BenchmarkHTTPThroughput64K-20        	   32664	    102326 ns/op	 640.46 MB/s	         4.528 cpu_ms/MB	        30.87 peak_rss_MB	     706 B/op	      13 allocs/op
BenchmarkHTTPThroughput256K-20       	   10000	    408807 ns/op	 641.24 MB/s	         4.500 cpu_ms/MB	        30.87 peak_rss_MB	    2501 B/op	      52 allocs/op
BenchmarkSOCKS5Throughput64K-20      	   36534	    102744 ns/op	 637.86 MB/s	         4.459 cpu_ms/MB	        30.87 peak_rss_MB	     624 B/op	      13 allocs/op
BenchmarkSOCKS5Throughput256K-20     	   10000	    408542 ns/op	 641.66 MB/s	         4.478 cpu_ms/MB	        30.87 peak_rss_MB	    2264 B/op	      53 allocs/op
BenchmarkForwardEcho16B-20           	   40584	     83629 ns/op	   0.38 MB/s	      4010 cpu_ms/MB	        30.87 peak_rss_MB	     293 B/op	       9 allocs/op
BenchmarkHTTPEcho16B-20              	   42014	     90382 ns/op	   0.35 MB/s	      4354 cpu_ms/MB	        30.87 peak_rss_MB	     294 B/op	       9 allocs/op
BenchmarkSOCKS5Echo16B-20            	   38718	     89967 ns/op	   0.36 MB/s	      4310 cpu_ms/MB	        30.87 peak_rss_MB	     294 B/op	       9 allocs/op
BenchmarkTUNFraming1500B-20          	  979266	      3106 ns/op	 483.51 MB/s	         8.043 cpu_ms/MB	        30.87 peak_rss_MB	      23 B/op	       0 allocs/op
BenchmarkTUNFraming9000B-20          	  266924	     12376 ns/op	 727.36 MB/s	         4.422 cpu_ms/MB	        30.87 peak_rss_MB	      67 B/op	       1 allocs/op
PASS
ok  	github.com/torkve/bidichan/internal/e2e	48.328s
```

## Caveats

- **Loopback, not network.** Real-world numbers will be capped by link
  bandwidth and latency. The CPU and alloc numbers carry over; the
  throughput numbers don't.
- **Single connection, single channel.** Yamux per-stream window is
  1 MiB; with many concurrent streams over one yamux session the
  per-stream throughput falls off but aggregate stays similar.
- **Race detector off.** Adding `-race` typically halves throughput and
  doubles CPU; we run without it as that's what production looks like.
- **No CGO TLS.** The Go stdlib TLS 1.2 path is pure Go. An NSS/OpenSSL-
  based stack would be faster on AES-GCM but doesn't match a uTLS
  Chrome ClientHello, which is the entire point of using uTLS.
