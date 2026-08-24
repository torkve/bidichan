# bidichan on Keenetic

An opkg package for Keenetic routers, built for the MediaTek MT7621 SoC used
by the **Keenetic Ultra (KN-1810)** and its siblings — little-endian,
soft-float MIPS, which Keenetic and Entware both call `mipsel`.

Installation goes through **Entware**. Keenetic's OPKG component is built
around it: `ndm` runs its "Opkg shell" with `/opt/bin/sh` and requires that
interpreter to live inside `/opt`, and Entware is what puts a shell there.
bidichan itself needs nothing from Entware — it is a single statically
linked binary, and the init script does not source `rc.func` — but the
platform does.

Everything fits in internal flash: the OPKG partition is around **27 MB** on
these models, Entware's base is about **8 MB**, and bidichan installs to
about **9.2 MB**.

## Build

```sh
make keenetic
# -> dist/bidichan_<version>_mipsel-3.4.ipk
```

Cross-compiles a static `GOARCH=mipsle GOMIPS=softfloat` binary (soft-float
because the userland is; a hard-float build faults on the first FP op) and
wraps it with `ar`/`tar` — no opkg-utils needed.

## Install — in this order

The order matters: Entware must be in place before the package, because
`opkg` itself comes from Entware.

### 1. Enable OPKG in the firmware

Web UI → **System settings → Component options**: install the **OPKG**
component.

### 2. Point OPKG at internal storage

Web UI → **OPKG Package Manager**: set *Drive* to **Internal storage**,
confirm access is enabled for your user, Save.

To use a USB drive instead, select that volume here; the rest is identical.

### 3. Install Entware

Web UI → **Applications → USB Devices → Internal storage**: create a folder
named `install`, and upload Entware's mipsel installer into it:

<https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz>

Then from the Keenetic CLI (telnet/ssh):

```
opkg disk storage:/
```

The firmware mounts the partition at `/opt` and inflates the installer. Give
it a moment, then confirm Entware is alive:

```sh
exec sh
opkg update
```

`exec sh` drops you from the NDMS CLI into a shell. If `opkg update` works,
step 3 is done.

### 4. Install bidichan

Grab `bidichan_<version>_mipsel-3.4.ipk` from the project's
[GitHub releases](https://github.com/torkve/bidichan/releases) (or build it
yourself with `make keenetic`), upload it through the same web UI file
manager (**Internal storage** is `/opt`), then:

```sh
exec sh
opkg install /opt/bidichan_<version>_mipsel-3.4.ipk
```

Installing generates a PSK and prints it — see **PSK** below.

### 5. Configure and start

```sh
vi /opt/etc/bidichan/bidichan.conf      # addr, hostname, channels
vi /opt/etc/init.d/S60bidichan          # the MODE line: connect or listen
/opt/etc/init.d/S60bidichan start       # also: stop | restart | status
```

### 6. Optional — TUN channels

Only if you use **tun** channels; forward, SOCKS5, HTTP and shell do not
need it:

```sh
opkg install ip-full
```

## PSK

A PSK is generated automatically at install, and again on first start if it
is still missing, into `/opt/etc/bidichan/psk.hex` (mode 600). It is printed
once — **copy that value to the other peer; both ends must match.**

It never overwrites an existing key, so upgrades and restarts keep the
current one, and it does nothing if you set an inline `psk =` yourself. To
roll it deliberately:

```sh
rm /opt/etc/bidichan/psk.hex
/opt/etc/init.d/S60bidichan genpsk
/opt/etc/init.d/S60bidichan restart
```

## Autostart and autorestart

**Autostart** needs no setup. Entware's `/opt/etc/initrc` (`rc.unslung`)
runs every `/opt/etc/init.d/S*` at boot, so `S60bidichan` is invoked. The
firmware calls boot scripts with no argument, so the script treats "no
argument" as `start`, and it uses `setsid` where available so the firmware's
24-second per-script timeout cannot take the service down with it.

**Autorestart is ours.** Neither the firmware nor Entware's `rc.func`
supervises anything — if the daemon dies, nothing brings it back. So `start`
launches a small supervisor that re-runs the binary whenever it exits:

- the restart delay starts at 5s and doubles to a 300s ceiling, so a bad
  config cannot spin the CPU respawning a process that will never start;
- a run lasting 60s or more counts as healthy and resets the delay, so an
  occasional crash after long uptime is retried at once;
- `stop` kills the supervisor first, so it cannot respawn the daemon during
  shutdown, and kills the daemon directly if the supervisor died itself.

`status` reports three states: running, not running, and "not running but
the supervisor is retrying".

Logs go to `/opt/var/log/bidichan.log`, rotated once at 512 KB so they
cannot fill a 27 MB partition.

## Notes

- `/opt/etc/bidichan/bidichan.conf` and `/opt/etc/init.d/S60bidichan` are
  registered as opkg `conffiles`, so your edits survive package upgrades.
- On a firmware update or factory reset, treat `/opt` as expendable — keep a
  copy of your config and PSK.
- There is no supported way to give a third-party package its own settings
  page in the Keenetic web UI; NDMS ships no LuCI-style plugin API. The UI's
  role here is storage and file upload. Configuration and start/stop happen
  over the console.
