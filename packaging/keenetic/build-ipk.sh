#!/bin/sh
# Assemble the opkg .ipk for Keenetic from a prebuilt binary.
#
# FORMAT. An .ipk here is the legacy ipkg flavour: a GZIPPED TAR whose
# members are, in this order,
#   ./debian-binary  ./data.tar.gz  ./control.tar.gz
# NOT the Debian-style `ar` archive. Entware's opkg rejects an ar archive
# outright with
#   pkg_init_from_file: Malformed package file <name>.ipk
# and every package in the Entware mipsel-3.4 feed is a gzipped tar --
# verified against xz-utils, kexec-tools and 6relayd from
# https://bin.entware.net/mipselsf-k3.4/ , which begin 1f 8b (gzip), not
# 21 3c 61 72 63 68 3e ("!<arch>").
#
# Note this cannot be checked with `ar t` or `file`: GNU ar happily reads
# back an ar archive it just wrote, and `file` cheerfully calls it a valid
# "Debian binary package". Only the target's parser disagrees, so the
# structural assertions at the bottom of this script exist to catch a
# regression before it reaches a release.
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

# ---- pack. Deterministic tars: fixed owner/mtime, explicit format. ----
# $TARFLAGS is deliberately left unquoted at the call sites below: it is a
# list of flags that must word-split. Quoting it (as shellcheck's SC2086
# suggests) would pass the whole string as one argument and break tar.
# shellcheck disable=SC2086
TARFLAGS="--numeric-owner --owner=0 --group=0 --mtime=@0 --format=gnu"

# `-C dir .` rather than naming members: the reference packages carry a
# leading "./" entry in both inner tars, so match that.
tar $TARFLAGS -C "$DATA" -czf "$WORK/data.tar.gz"    .
tar $TARFLAGS -C "$CTRL" -czf "$WORK/control.tar.gz" .
printf '2.0\n' > "$WORK/debian-binary"

OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
rm -f "$OUT"
# Members are listed explicitly, in the reference order. No --sort here:
# sorting by name would put control.tar.gz first and debian-binary last,
# and debian-binary is the format marker that should lead.
tar $TARFLAGS -C "$WORK" -czf "$OUT" ./debian-binary ./data.tar.gz ./control.tar.gz

# ---- verify. These assertions encode the reference layout so a malformed
# package fails the build rather than a router. ----
fail() { echo "build-ipk: BROKEN PACKAGE: $*" >&2; exit 1; }

magic="$(dd if="$OUT" bs=2 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
[ "$magic" = "1f8b" ] || fail "outer container is not gzip (magic $magic); opkg needs a gzipped tar, not ar"

members="$(tar tzf "$OUT" | tr '\n' ' ')"
[ "$members" = "./debian-binary ./data.tar.gz ./control.tar.gz " ] \
    || fail "outer members/order wrong: [$members]"

[ "$(tar xzOf "$OUT" ./debian-binary)" = "2.0" ] || fail "debian-binary is not 2.0"

tar xzOf "$OUT" ./control.tar.gz | tar tzf - | grep -qx './control' \
    || fail "control.tar.gz has no ./control"
tar xzOf "$OUT" ./data.tar.gz | tar tzf - | grep -qx './opt/sbin/bidichan' \
    || fail "data.tar.gz has no ./opt/sbin/bidichan"

# opkg's tar reader hard-requires ustar magic: get_header_tar() bails out on
# anything else, and the v7/oldgnu fallback is compiled out. --format=gnu
# writes "ustar  \0", which satisfies it; --format=v7 would not.
ustar="$(zcat "$OUT" | dd bs=1 skip=257 count=5 2>/dev/null)"
[ "$ustar" = "ustar" ] || fail "outer tar lacks ustar magic (got '$ustar')"

# GNU long-name records (typeflag 'L') are compiled out of opkg's reader, so
# a path over 100 bytes would install SILENTLY TRUNCATED rather than failing.
long="$(tar xzOf "$OUT" ./data.tar.gz | tar tzf - | awk 'length($0) > 100')"
[ -z "$long" ] || fail "path over 100 bytes would be truncated on install: $long"

echo "built $OUT ($(du -h "$OUT" | cut -f1), arch=$ARCH, version=$VERSION)"
echo "  format verified: gzipped tar, members in reference order"
