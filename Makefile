# Building bidichan.
#
# The stripped flags are the point of this file: a plain `go build` leaves the
# symbol table and DWARF in place, which is a third of the binary and dead
# weight on a small box. The Dockerfile carries the same flags inline — the two
# are kept in step by hand rather than by making the image depend on make.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/torkve/bidichan/internal/cli.version=$(VERSION)
GOFLAGS := -trimpath -ldflags "$(LDFLAGS)"

# Nothing here needs libc, and a static binary is what makes one artefact run on
# whatever the controller turns out to be. Scoped to the build recipes rather
# than exported: `go test -race` needs cgo, and turning it off globally makes
# the test target fail outright.
CGO := CGO_ENABLED=0

# The dist artefacts are phony despite being real paths: without it make sees
# the file, calls it up to date and ships a stale binary after a source change.
# go build is incremental anyway, so rebuilding unconditionally costs nothing.
DIST := dist/bidichan-linux-arm64 dist/bidichan-linux-armv7 dist/bidichan-linux-amd64

# Keenetic (MT7621, e.g. KN-1810 Ultra) is little-endian soft-float MIPS, and
# Entware's opkg feed for it calls that arch mipsel-3.4. opkg versions carry no
# leading "v", so strip the one `git describe` emits.
KEENETIC_ARCH   := mipsel-3.4
OPKG_VERSION    := $(VERSION:v%=%)
KEENETIC_IPK    := dist/bidichan_$(OPKG_VERSION)_$(KEENETIC_ARCH).ipk

.PHONY: all build dist test clean keenetic $(DIST) dist/bidichan-linux-mipsle

all: build

build:
	$(CGO) go build $(GOFLAGS) -o bidichan .

# The architectures a small Linux controller is actually likely to be. GOARM=7
# because anything older has no meaningful presence left.
dist: $(DIST)

dist/bidichan-linux-arm64:
	$(CGO) GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $@ .

dist/bidichan-linux-armv7:
	$(CGO) GOOS=linux GOARCH=arm GOARM=7 go build $(GOFLAGS) -o $@ .

dist/bidichan-linux-amd64:
	$(CGO) GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $@ .

# Keenetic build: the mipsle binary plus an installable .ipk. GOMIPS=softfloat
# because the Entware mipsel-3.4 userland is soft-float; a hard-float binary
# faults on the first FP op. Static (CGO off) so it needs nothing from the
# firmware's libc.
dist/bidichan-linux-mipsle:
	$(CGO) GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build $(GOFLAGS) -o $@ .

keenetic: dist/bidichan-linux-mipsle
	packaging/keenetic/build-ipk.sh dist/bidichan-linux-mipsle $(OPKG_VERSION) $(KEENETIC_ARCH) $(KEENETIC_IPK)

test:
	go test -race ./...

clean:
	rm -f bidichan
	rm -rf dist/bidichan-linux-* dist/bidichan_*.ipk
