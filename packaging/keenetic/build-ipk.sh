#!/bin/sh
# Assemble the opkg .ipk for Keenetic from a prebuilt binary.
#
# An .ipk is an ar archive of three members, in this order:
#   debian-binary  control.tar.gz  data.tar.gz
# Built with plain ar/tar/gzip, so no opkg-utils install is needed.
#
# This targets `opkg install` on a router that already has Entware. The
# firmware's own /opt/install inflater is NOT a supported target here: it
# parses archives as gzipped tar (an ar archive fails with "bad size"),
# and in any case it cannot run a package's init script without a shell at
# /opt/bin/sh, which Entware is what provides.
#
# Usage: build-ipk.sh <binary> <version> <arch> <out.ipk>
set -eu

BIN="$1"; VERSION="$2"; ARCH="$3"; OUT="$4"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -f "$BIN" ] || { echo "build-ipk: binary not found: $BIN" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- data tree (what lands under /opt on the router) ----
DATA="$WORK/data"
mkdir -p "$DATA/opt/sbin"
cp -a "$HERE/opt/." "$DATA/opt/"
install -m 0755 "$BIN" "$DATA/opt/sbin/bidichan"
chmod 0755 "$DATA/opt/etc/init.d/S60bidichan"
chmod 0644 "$DATA/opt/etc/bidichan/bidichan.conf"

# Installed-Size in bytes, opkg convention.
ISIZE="$(du -sb "$DATA/opt" | cut -f1)"

# ---- control tree (metadata + maintainer scripts) ----
CTRL="$WORK/control"
mkdir -p "$CTRL"
sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$ARCH/" -e "s/@ISIZE@/$ISIZE/" \
    "$HERE/control/control.in" > "$CTRL/control"
cp "$HERE/control/conffiles" "$CTRL/conffiles"
install -m 0755 "$HERE/control/postinst" "$CTRL/postinst"
install -m 0755 "$HERE/control/prerm"    "$CTRL/prerm"

# ---- pack. Deterministic tars: sorted, fixed owner/mtime. ----
# $TARFLAGS is deliberately left unquoted at the call sites below: it is a
# list of flags that must word-split. Quoting it (as shellcheck's SC2086
# suggests) would pass the whole string as one argument and break tar.
# shellcheck disable=SC2086
TARFLAGS="--numeric-owner --owner=0 --group=0 --sort=name --mtime=@0"
tar $TARFLAGS -C "$DATA" -czf "$WORK/data.tar.gz"    ./opt
tar $TARFLAGS -C "$CTRL" -czf "$WORK/control.tar.gz" ./control ./conffiles ./postinst ./prerm
printf '2.0\n' > "$WORK/debian-binary"

OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
rm -f "$OUT"
( cd "$WORK" && ar rc "$OUT" debian-binary control.tar.gz data.tar.gz )

echo "built $OUT ($(du -h "$OUT" | cut -f1), arch=$ARCH, version=$VERSION)"
