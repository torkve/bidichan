# bidichan

A bidirectional transport that looks like HTTPS over TLS 1.2 on the wire.
Once two peers complete the handshake they are equal — either side can open
or close channels through the other end.

Channel kinds:

| kind     | what it does                                                  |
| -------- | ------------------------------------------------------------- |
| forward  | SSH-style direct (`-L`) or reverse (`-R`) TCP port forwarding |
| http     | HTTP proxy (CONNECT + absolute-URI) terminating on the peer   |
| socks5   | SOCKS5 proxy (CONNECT, no-auth) terminating on the peer       |
| tun      | L3 TUN device with packets framed across one yamux stream     |

Anyone who hits the listener with the wrong SNI, the wrong PSK, or just an
ordinary HTTPS request gets the canonical nginx welcome page byte-for-byte
and then a clean close. There is no visible "bidichan" port from the
outside — only an HTTPS server.

## Build

The repository is a plain Go module. Requires Go 1.25+.

```sh
go build ./...
```

A `bidichan` binary is produced in the module root. Tests:

```sh
go test -race ./...
```

## Quick start

The two ends share a hex-encoded pre-shared key (`--psk`) and an SNI
hostname (`--hostname`).

Generate a PSK once:

```sh
head -c 32 /dev/urandom | xxd -p -c 64
# -> e.g. b7e3c6e1...d39c6a7a (use the same value on both sides)
```

### Server side

```sh
bidichan listen \
  --addr 0.0.0.0:443 \
  --hostname cdn.example.com \
  --psk <hex>
```

By default a self-signed ECDSA cert is generated in memory. To present a
real cert (e.g. one from Let's Encrypt), pass `--cert` and `--key`.

### Client side

```sh
bidichan connect \
  --addr cdn.example.com:443 \
  --hostname cdn.example.com \
  --psk <hex>
```

The two processes form a single long-lived peer link. Both keep running
in the foreground; Ctrl-C / SIGTERM tears them down cleanly.

### Verify it's up

From either side:

```sh
bidichan status
```

prints the connected peers and any open channels.

## Opening channels

`channel open` is invoked on either side and tells the local daemon what to
ask the peer to set up. `--listen-side local` means the listener binds on
the side where you typed the command; `--listen-side remote` means it binds
on the other side. The same convention applies to `--tun-side` for TUN.

### Port forwarding

SSH-style shortcuts work and are the simplest path:

```sh
# direct forward: listen on this side's :8080, traffic egresses on the peer
bidichan channel open forward -L 8080:internal-api:8443

# reverse forward: listener binds on the peer at :2222, traffic egresses here
bidichan channel open forward -R 2222:127.0.0.1:22
```

The long form is equivalent and lets you bind a non-loopback interface:

```sh
bidichan channel open forward \
  --listen-side local \
  --listen-addr 0.0.0.0:8080 \
  --target  internal-api:8443
```

### HTTP and SOCKS5 proxies

```sh
# Start an HTTP proxy on this side, egressing via the peer's network:
bidichan channel open http --listen 127.0.0.1:3128

# Or a SOCKS5 proxy:
bidichan channel open socks5 --listen 127.0.0.1:1080
```

Now anything pointed at `127.0.0.1:3128` (or `:1080`) goes out via the peer.

You can also push the listener to the peer side:

```sh
bidichan channel open socks5 --listen-side remote --listen 0.0.0.0:1080
```

### TUN device

Both sides must run `channel open tun` because the device is a per-side
resource. Linux configures CIDR + MTU automatically via `ip` (requires
`CAP_NET_ADMIN`).

```sh
# side A
sudo bidichan channel open tun --tun-side local --cidr 10.42.0.1/24 --name bc0

# side B (corresponding peer)
sudo bidichan channel open tun --tun-side local --cidr 10.42.0.2/24 --name bc0
```

You then add routes (`ip route add ... dev bc0`) as you'd configure any
point-to-point link.

### Close a channel

```sh
bidichan status                 # find the channel ID
bidichan channel close --id 1
```

## Multiple peers

If a daemon has more than one peer connected (e.g. a listening server with
several clients), pass `--peer <ID>` to disambiguate. The CLI accepts any
unique ID prefix.

## Multiple daemons on one host

Each daemon writes a Unix socket to `$XDG_RUNTIME_DIR/bidichan-<pid>.sock`
(falling back to `/tmp`). The CLI auto-discovers a single socket; with more
than one running, pass `--socket /path/to/the.sock` explicitly. The same
flag is available on every CLI subcommand.

## DPI behaviour

- The client uses [uTLS](https://github.com/refraction-networking/utls)
  with the `HelloChrome_Auto` preset, so the ClientHello (cipher suites,
  extension list and ordering, GREASE values, supported groups) matches
  the latest Chrome. JA3/JA4 fingerprinting cannot distinguish it from
  real browser traffic.
- The session negotiates TLS 1.2 (server-side pinned). Chrome offers
  1.3 + 1.2 in its ClientHello, so the wire shape is exactly what a
  Chrome ↔ old-nginx session looks like.
- The application-layer handshake is an HTTP/1.1 `Upgrade: bidichan/1`
  request. Auth is a Bearer header carrying
  `HMAC-SHA256(PSK, "client" || nonce || timestamp || tls_unique)` where
  `tls_unique` is the channel binding from RFC 5929. The server's
  `101 Switching Protocols` includes the matching server-role MAC for
  mutual authentication.
- Replay window: ±90 s. Nonces are remembered for the window.
- Wrong SNI, wrong Host, missing Upgrade, missing or bad MAC, replayed
  nonce, or just an ordinary HTTPS request — all produce a byte-for-byte
  copy of the Ubuntu nginx default page and a clean close.

### Caveats

- The certificate is self-signed by default. The wire shape is unchanged
  (plenty of real servers serve self-signed certs), but a real cert is
  trivial to bolt on with `--cert` / `--key`.
- The server's ServerHello is generated by Go's standard library, not by
  uTLS — it's structurally a normal TLS 1.2 ServerHello but does not
  perfectly match nginx's. Most DPI fingerprints the *client* hello, not
  the server hello, so this is rarely an issue in practice.
- The TUN channel needs root or `CAP_NET_ADMIN`.

## Layout

```
internal/
  transport/   TLS 1.2 listener/dialer, nginx decoy, PSK+TLS-exporter auth
  peer/        yamux session, JSON control protocol, channel registry
  channel/     forward, HTTP/SOCKS5 proxy, and TUN implementations
  daemon/      long-running process: peers + the local CLI control socket
  cli/         command-line surface
  e2e/         end-to-end tests
main.go        entry point that dispatches to internal/cli
```
