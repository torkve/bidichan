# syntax=docker/dockerfile:1.6

# ---- Build ----
# Pinned to 1.25-alpine so the build is reproducible. Bump in lockstep with
# go.mod when the toolchain in go.mod moves.
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache module downloads in their own layer so editing source code doesn't
# invalidate the deps layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is unused — water uses pure syscalls, crypto/tls is stdlib, uTLS is
# pure Go — so disabling cgo lets the binary run on any alpine without
# pulling in libc dependencies.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/bidichan ./

# ---- Runtime ----
FROM alpine:3.20

# iproute2 supplies /sbin/ip, which bidichan shells out to when configuring
# a TUN device. ca-certificates is there for anything that ever needs to
# validate a real-cert peer.
RUN apk add --no-cache iproute2 ca-certificates tzdata && \
    mkdir -p /run/bidichan /var/lib/bidichan

COPY --from=build /out/bidichan /usr/local/bin/bidichan

# Runs as root by default. Container isolation (user / pid / mount
# namespaces) is the security boundary; running as root inside a
# non-privileged container is the same pattern most official images use,
# and it keeps the image simple — no setcap dance fighting Docker's
# default capability bounding set, which excludes CAP_NET_ADMIN.
#
# Operators who want to run as nonroot can pass --user 1000:1000 on
# `docker run`; they will then need to use a high port internally and let
# docker map -p 443:HIGHPORT. TUN, low-port binding, and TLS termination
# on :443 inside the container all require root (or the matching file
# capabilities, set in a derived image).

ENV XDG_RUNTIME_DIR=/run/bidichan

# Default control-socket location inside the container. Mount /run/bidichan
# from the host (or another container, e.g. nginx) to expose it.
VOLUME ["/run/bidichan"]

# TLS-mode listener default. Adjust at run time via --addr / --unix-socket.
EXPOSE 443/tcp

ENTRYPOINT ["/usr/local/bin/bidichan"]
CMD ["help"]
