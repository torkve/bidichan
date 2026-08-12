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

.PHONY: all build dist test clean $(DIST)

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

test:
	go test -race ./...

clean:
	rm -f bidichan
	rm -rf dist/bidichan-linux-*
