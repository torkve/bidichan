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
- The server restricts its cipher list to the ECDHE-ECDSA / ECDHE-RSA
  AEAD suites real nginx negotiates with modern clients, biasing the
  JA3S cipher slot toward a plausible value.
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

### Behind a real nginx (recommended for full ServerHello parity)

The ServerHello we generate is from Go's standard library. The cipher
choice is tuned to be nginx-like (see above), but the *extension list
and order* still come from Go and a JA3S inspector could in principle
tell that apart from real nginx. For full parity, deploy bidichan behind
a real nginx that terminates TLS and forwards the inner protocol over a
unix socket:

```sh
bidichan listen \
  --unix-socket /run/bidichan.sock \
  --hostname cdn.example.com \
  --psk <hex>
```

```nginx
# /etc/nginx/sites-enabled/bidichan
upstream bidichan { server unix:/run/bidichan.sock; }
server {
    listen 443 ssl http2;
    server_name cdn.example.com;
    ssl_certificate     /etc/letsencrypt/live/cdn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location = /events {
        proxy_pass http://bidichan;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
    }
    location / {
        # Anything other than /events gets the real nginx default page,
        # not bidichan's lookalike.
        return 200 'real nginx server';
    }
}
```

On the client side, tell bidichan not to expect a shared TLS-unique
binding (since nginx has terminated TLS between the client and the
server's plain socket, the two halves see different TLS sessions and no
shared binding exists):

```sh
bidichan connect \
  --addr cdn.example.com:443 \
  --hostname cdn.example.com \
  --psk <hex> \
  --no-tls-binding
```

In this deployment the *real* nginx ServerHello goes on the wire, so the
JA3S fingerprint is literally that of the production nginx version
serving the rest of the site.

### Caveats

- The default cert is self-signed. The wire shape is unchanged (plenty
  of real servers serve self-signed certs), but a real cert is trivial
  to bolt on with `--cert` / `--key` — or just use the nginx-front
  deployment, which already has a real cert.
- The TUN channel needs root or `CAP_NET_ADMIN`.
- `--no-tls-binding` drops the channel binding from the auth HMAC. The
  PSK + nonce + timestamp window (±90s) still protect against replay,
  but an attacker who controls the TLS terminator could in principle
  replay an upgrade into a different TLS session.

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
