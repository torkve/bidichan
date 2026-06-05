# bidichan

A bidirectional transport that looks like a normal HTTPS WebSocket service on
the wire (TLS 1.3, a genuine RFC 6455 upgrade). Once two peers complete the
handshake they are equal — either side can open or close channels through the
other end.

Channel kinds:

| kind     | what it does                                                  |
| -------- | ------------------------------------------------------------- |
| forward  | SSH-style direct (`-L`) or reverse (`-R`) TCP port forwarding |
| http     | HTTP proxy (CONNECT + absolute-URI) terminating on the peer   |
| socks5   | SOCKS5 proxy (CONNECT, no-auth) terminating on the peer       |
| tun      | L3 TUN device with packets framed across one yamux stream     |

Any connection with the wrong SNI, the wrong PSK, or an ordinary HTTPS request
is transparently proxied to a real web backend you configure (`--decoy-backend`),
so it gets a genuine site — real 404s for unknown paths and all. Without a
backend configured it falls back to a static nginx welcome page. From the
outside there is only an HTTPS server.

> **Recommended deployment:** run bidichan in plain mode behind a real
> nginx/caddy that terminates TLS — see
> [Recommended: behind a real nginx](#recommended-behind-a-real-nginx). Then the
> TLS handshake, certificate, ALPN, and the response to unauthenticated requests
> are all served by the front server.

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

By default a self-signed ECDSA cert is generated in memory. The client
**verifies the server certificate**, so for a standalone server either present a
publicly-trusted cert with `--cert` / `--key` (and let the client use the system
trust store), or use a stable self-signed cert and point the client at it with
`--cacert` (see [Client side](#client-side)). The ephemeral in-memory default
changes on every restart and cannot be pinned — pass `--cert` / `--key` for a
stable one. Best of all, use the
[behind-a-real-nginx](#recommended-behind-a-real-nginx) deployment, where the
front server already has a real, publicly-trusted cert.

The WebSocket upgrade path is derived from the PSK and logged at startup
(`websocket upgrade path is /…`). Pass `--path` on both ends to pin a specific
path instead (useful for matching a reverse-proxy `location`).

### Client side

```sh
bidichan connect \
  --addr cdn.example.com:443 \
  --hostname cdn.example.com \
  --psk <hex>
```

If the server uses a publicly-trusted cert, that's all. For a self-signed or
private-CA server, add `--cacert /path/to/cert-or-ca.pem` so the client can
verify it. (Behind nginx with a real cert, no `--cacert` is needed.)

The two processes form a single long-lived peer link. Both keep running
in the foreground; Ctrl-C / SIGTERM tears them down cleanly.

### Verify it's up

From either side:

```sh
bidichan status
```

prints the connected peers and any open channels.

### Config files (profiles)

Repeating `--addr`, `--hostname`, and `--psk` on every invocation gets
tedious. `listen` and `connect` also accept a profile name — a small
`key = value` file that holds the settings once:

```ini
# ~/.config/bidichan/mypeer.conf  (mode 0600)
addr     = cdn.example.com:443
hostname = cdn.example.com
psk-file = ~/.config/bidichan/mypeer.psk
```

Then:

```sh
bidichan listen mypeer            # or:  bidichan listen --config mypeer
bidichan connect mypeer           # or:  bidichan connect --config mypeer
```

Profile lookup order: `$XDG_CONFIG_HOME/bidichan/<name>.conf`
(default `~/.config/bidichan/`), then `/etc/bidichan/<name>.conf`.
`--config` also accepts a literal path. Any CLI flag overrides the
file value, so `bidichan connect mypeer --psk DEAD…` uses the
override.

Recognised keys mirror the CLI flags one-to-one (without the `--`
prefix): `addr`, `unix-socket`, `hostname`, `psk`, `psk-file`,
`no-tls-binding`, `cert`, `key`, `socket`. Unknown keys are a hard
error so typos surface at startup. `~/` and `$VAR` are expanded in
path-valued keys. The same file can be shared between server and
client invocations — keys that don't apply to a given side are
silently ignored.

A fully-commented example with every key lives at
[`docs/config/example.conf`](docs/config/example.conf).

### Shell completion

`bidichan completion <shell>` emits a completion script. Subcommands,
per-subcommand flags, `channel open` kinds, and profile names (from
`$XDG_CONFIG_HOME/bidichan` and `/etc/bidichan`) all get completed on
`<TAB>`.

```sh
# bash, current shell only
source <(bidichan completion bash)

# bash, system-wide
bidichan completion bash | sudo tee /etc/bash_completion.d/bidichan

# zsh, per-user — pick the first fpath entry that's under $HOME
bidichan completion zsh > "${fpath[1]}/_bidichan"

# fish
bidichan completion fish > ~/.config/fish/completions/bidichan.fish
```

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

## Running as a service

Two supported deployment shapes ship with the repo: a Docker image and a
systemd template unit. Pick whichever fits your environment.

### Docker

A multi-stage `Dockerfile` builds a static, CGO-disabled binary on
`golang:1.25-alpine` and ships it on `alpine:3.20` together with
`iproute2` (needed when bidichan configures a TUN device).

```sh
docker build -t bidichan:latest .
```

The image runs as root inside the container because container
namespaces are the security boundary — running as root inside an
unprivileged container is the same pattern most official images use,
and it sidesteps the file-capability dance that breaks under Docker's
default capability bounding set (no `CAP_NET_ADMIN`).

The image exposes `/run/bidichan` as a volume. Mount it on the host (or
share it with a sibling container — e.g. nginx) to reach the local
control socket from the host CLI.

**Server, plain TCP+TLS on :443:**

```sh
docker run -d --name bidichan-server \
  --restart=unless-stopped \
  --network host \
  -v /run/bidichan-server:/run/bidichan \
  bidichan:latest \
  listen --addr :443 --hostname cdn.example.com --psk "$PSK" \
         --socket /run/bidichan/control.sock
```

(`--network host` is the simplest way to get :443 on the host. Use
`-p 443:443` instead if you prefer port mapping.)

**Server, plain mode behind nginx (full ServerHello parity):**

```sh
docker run -d --name bidichan-plain \
  --restart=unless-stopped \
  -v /run/bidichan-plain:/run/bidichan \
  bidichan:latest \
  listen --unix-socket /run/bidichan/data.sock --hostname cdn.example.com \
         --psk "$PSK" --socket /run/bidichan/control.sock
```

Mount the same `/run/bidichan-plain` into your nginx container at the
path its config expects, and point `proxy_pass` at
`http://unix:/run/bidichan/data.sock`.

**Client:**

```sh
docker run -d --name bidichan-client \
  --restart=unless-stopped \
  --network host \
  -v /run/bidichan-client:/run/bidichan \
  bidichan:latest \
  connect --addr cdn.example.com:443 --hostname cdn.example.com \
          --psk "$PSK" --socket /run/bidichan/control.sock
```

**TUN channel inside a container** needs both the device and the
capability:

```sh
docker run -d --name bidichan-tun \
  --cap-add=NET_ADMIN --device /dev/net/tun \
  --network host \
  -v /run/bidichan-tun:/run/bidichan \
  bidichan:latest \
  connect --addr cdn.example.com:443 --hostname cdn.example.com \
          --psk "$PSK" --socket /run/bidichan/control.sock
```

**Driving the CLI from the host** — point it at the mounted socket:

```sh
bidichan status --socket /run/bidichan-server/control.sock
bidichan channel open forward -L 8080:internal-api:8443 \
  --socket /run/bidichan-client/control.sock
```

If you don't have the bidichan binary on the host, exec into the
container instead:

```sh
docker exec -it bidichan-client bidichan channel open socks5 \
  --listen 0.0.0.0:1080 --listen-side remote
```

### systemd

A templated unit and example environment files live in `docs/systemd/`.
Each instance reads `/etc/bidichan/<instance>.env` for its full argument
list.

Install once:

```sh
# binary
install -m 0755 bidichan /usr/local/bin/

# user + group
useradd --system --no-create-home --shell /usr/sbin/nologin bidichan

# unit
install -m 0644 docs/systemd/bidichan@.service /etc/systemd/system/
systemctl daemon-reload
```

Then per instance:

```sh
install -d -m 0750 -o root -g bidichan /etc/bidichan

# Pick the right example. Each defines BIDICHAN_FLAGS.
install -m 0640 -o root -g bidichan \
  docs/systemd/listen.env.example /etc/bidichan/listen.env
$EDITOR /etc/bidichan/listen.env   # set the hostname + PSK

systemctl enable --now bidichan@listen
```

A per-instance subdirectory `/run/bidichan/<instance>/` is created by
systemd's `RuntimeDirectory=bidichan/%i`, chowned to
`bidichan:bidichan` at start and cleaned up at stop. Use it as the
`--socket` path (the example envs already point each instance at its
own subdir). For the plain-mode behind-nginx setup, add nginx's user to
the `bidichan` group so its worker can traverse the runtime dir:

```sh
usermod -aG bidichan nginx     # or www-data, depending on distro
systemctl restart nginx
```

The unit grants `CAP_NET_BIND_SERVICE` (for `:443`) and
`CAP_NET_ADMIN` (for TUN) as ambient capabilities so the unprivileged
`bidichan` user can bind low ports and create TUN devices without
`setuid 0`. Drop one or both from `AmbientCapabilities=` /
`CapabilityBoundingSet=` in your installed copy if an instance doesn't
need them.

`/dev/net/tun` is whitelisted via `DeviceAllow=`. Everything else is
locked down (`NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectKernelTunables`, syscall filter, etc.).

Multiple instances run side by side: `bidichan@listen`,
`bidichan@connect`, `bidichan@plain`, etc., each reading its own env
file and writing its own control socket under
`/run/bidichan/<instance>/control.sock`. The CLI's auto-discovery
won't help here (it searches `$XDG_RUNTIME_DIR`, not `/run/bidichan/`),
so pass `--socket` explicitly.

## Two-hop deployment (ProxyJump-style)

When the final target sits behind an intermediate host — the same
shape SSH gives with `ProxyJump` — bidichan supports A → B → C
end-to-end with no special server code on the jump host. B is just a
normal `bidichan listen` server. The inner TLS+PSK session terminates
at C, so **B only ever sees ciphertext** and learns neither C's PSK
nor the application payload.

```
           outer bidichan (B's TLS+PSK+yamux)
A ─────────────────────────────────────────► B
                                              │ TCP egress from B's
                                              │ forward channel
                                              ▼
                                              C   (port 443)
A ════════════════════════════════════════════► C
           inner bidichan (C's TLS+PSK+yamux), end-to-end
                — B sees only the inner ciphertext —
```

On client A, run two daemons. The first owns the connection to B; the
second owns the connection to C and dials it *through* the forward
channel the first daemon set up:

```sh
# 1. Peer connection through B (the jump host).
bidichan connect \
  --addr jump.example.com:443 \
  --hostname jump.example.com \
  --psk "$B_PSK" \
  --socket /run/bidichan-jump.sock &

# 2. Forward channel through B whose target is C's bidichan port.
bidichan channel open forward \
  -L 2222:cdn.example.com:443 \
  --socket /run/bidichan-jump.sock

# 3. Peer connection to C that dials the forward listener
#    rather than C directly. The inner TLS+PSK session
#    terminates at C; B sees only ciphertext.
bidichan connect \
  --addr 127.0.0.1:2222 \
  --hostname cdn.example.com \
  --psk "$C_PSK" \
  --socket /run/bidichan-cdn.sock &
```

After step 3 you drive channels normally against the cdn socket:

```sh
bidichan channel open socks5 \
  --listen 127.0.0.1:1080 \
  --socket /run/bidichan-cdn.sock
```

Trade-offs to know about:

- **TLS-in-TLS doubles per-byte CPU on A and C.** The single-hop
  number from [BENCHMARKS.md](BENCHMARKS.md) is ~4.5 ms/MB; two-hop is
  ~9 ms/MB. B's CPU cost is the same as single-hop (one TLS layer).
- **Two daemons on A, two sockets, two PIDs.** Under systemd, run the
  existing `bidichan@.service` twice (e.g. `bidichan@jump-B` and
  `bidichan@cdn-via-B`); the unit's `RuntimeDirectory=bidichan/%i`
  already keeps the sockets separate.
- **Pick a fixed loopback port** for step 2 (`2222` here) — it makes
  step 3 trivial. Using `:0` works too, but you have to look up the
  bound port via `bidichan status --socket /run/bidichan-jump.sock`
  before running step 3.
- **The jump host needs no special config.** B is a normal `bidichan
  listen`. C is a normal `bidichan listen`. The chain is composed
  entirely on the client side.
- **TUN through two hops** works but reduce the MTU (`--mtu 1300`)
  because each TLS layer eats ~30 bytes per packet.

## Protocol notes

> The recommended deployment is [behind a real nginx](#recommended-behind-a-real-nginx);
> in that mode the TLS layer and the response to unauthenticated requests are
> served by the real reverse proxy.

- **Client TLS:** the client uses
  [uTLS](https://github.com/refraction-networking/utls) with the current Chrome
  ClientHello (`HelloChrome_Auto`) for broad TLS interoperability, with the GREASE
  `encrypted_client_hello` (ECH) extension removed (`chromeNoECHSpec`) since some
  networks and middleboxes mishandle ECH and bidichan sends a cleartext SNI anyway.
- **TLS version:** the server offers TLS 1.2 and 1.3, so a modern client
  negotiates 1.3.
- **Application handshake:** a standard RFC 6455 WebSocket upgrade
  (`Upgrade: websocket`, `Sec-WebSocket-Key`/`-Accept`). The request path and the
  cookie names are derived from the PSK, so they are deployment-specific rather
  than fixed constants. Auth travels in a session cookie carrying
  `HMAC-SHA256(PSK, "client" || nonce || timestamp || binding)`; the server's
  `101 Switching Protocols` returns the matching server-role MAC in a `Set-Cookie`
  for mutual authentication.
- **Data phase:** after the `101`, the tunnel is carried inside RFC 6455 binary
  frames (client→server masked, server→client not) — yamux runs inside the frames,
  so the connection is standards-compliant WebSocket end to end. (nginx tunnels
  these bytes verbatim, so the framing is end-to-end between the two peers.)
- **ALPN / HTTP version:** the client offers `h2` + `application_settings`, but the
  WebSocket tunnel is HTTP/1.1 (nginx does not support RFC 8441 WebSocket-over-h2),
  so the bidichan endpoint must negotiate **http/1.1** — see the deployment note
  below. This is how any HTTP/1.1 WebSocket endpoint behaves.
- **Channel binding:** `binding` is the SHA-256 of the server certificate's
  SubjectPublicKeyInfo (an SPKI pin, à la RFC 5929 `tls-server-end-point`). A
  relay that terminates TLS with a *different* certificate derives a different
  binding and fails auth. (This replaced `tls-unique`, which only exists in TLS 1.2.)
- **Replay window:** ±90 s. Nonces are remembered for the window.
- **Unauthenticated requests:** wrong SNI/Host, a non-WebSocket request, a
  missing/bad MAC, a replayed nonce, or an ordinary HTTPS request are all
  transparently proxied to the real `--decoy-backend`, which returns its genuine
  responses (e.g. a real 404 for an unknown path). Without a backend configured,
  the built-in fallback is a static nginx page.
- **Timing:** both the TCP keepalive and the yamux keepalive are jittered per
  connection (≈20–40 s); the WebSocket layer also emits low-rate ping frames at
  randomised intervals as lightweight keepalive traffic.

### Recommended: behind a real nginx

Run bidichan in plain mode behind a real nginx/caddy that terminates TLS and
forwards the WebSocket upgrade over a unix socket. The TLS handshake, certificate
(real, e.g. Let's Encrypt), and the response to every non-secret path are then
served by the front server.

The bidichan endpoint must be served over **HTTP/1.1** (do not enable `http2` on
that server block): the client offers `h2`, but WebSocket-over-HTTP/2
(RFC 8441) is not supported by nginx, so the tunnel is HTTP/1.1 — as any
HTTP/1.1 WebSocket endpoint is. Put it on its own
`server_name` (e.g. a `ws.`-style host) so the rest of your site can still use
h2/h3.

```sh
# Pin a path that blends in with ordinary WebSocket apps, matching the nginx
# location below. (Omit --path to use the PSK-derived one, logged at startup.)
bidichan listen \
  --unix-socket /run/bidichan.sock \
  --hostname ws.example.com \
  --path /ws \
  --psk <hex>
```

```nginx
# /etc/nginx/sites-enabled/bidichan
upstream bidichan { server unix:/run/bidichan.sock; }
server {
    listen 443 ssl;             # NOTE: no "http2 on" — the WS tunnel is HTTP/1.1
    server_name ws.example.com;
    ssl_certificate     /etc/letsencrypt/live/ws.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ws.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location = /ws {
        proxy_pass http://bidichan;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
    }
    location / {
        # Everything else must be a real site, so a probe to any other path
        # behaves exactly like the host it claims to be. Serve real content or
        # proxy to a genuine upstream — do NOT return a canned string.
        proxy_pass http://127.0.0.1:8080;   # your real web app
    }
}
```

On the client side, pass `--no-tls-binding` (nginx terminates TLS, so the client
and the bidichan server see different TLS sessions and share no certificate
binding), and `--path` to match:

```sh
bidichan connect \
  --addr ws.example.com:443 \
  --hostname ws.example.com \
  --path /ws \
  --psk <hex> \
  --no-tls-binding
```

### Caveats

- The client always verifies the server certificate (system trust store, or
  `--cacert` for a self-signed / private CA). The in-memory default cert is
  ephemeral and cannot be pinned, so a standalone server should use `--cert` /
  `--key` (and the client `--cacert`), a publicly-trusted cert, or the nginx
  front.
- The TUN channel needs root or `CAP_NET_ADMIN`.
- `--no-tls-binding` drops the certificate channel binding from the auth HMAC;
  use it only behind a TLS-terminating reverse proxy. The client still verifies
  the proxy's certificate, so a relay must present a trusted cert. In standalone
  mode (binding present) a relay that swaps the certificate is additionally
  caught at the MAC check, because the binding is the SHA-256 of the server
  cert's public key and the two ends would derive different values.

## Layout

```
internal/
  transport/   TLS 1.3 listener/dialer, WebSocket auth+framing, cert binding, decoy
  peer/        yamux session, JSON control protocol, channel registry
  channel/     forward, HTTP/SOCKS5 proxy, and TUN implementations
  daemon/      long-running process: peers + the local CLI control socket
  cli/         command-line surface
  e2e/         end-to-end tests
main.go        entry point that dispatches to internal/cli
```
