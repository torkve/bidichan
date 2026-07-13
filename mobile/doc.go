//go:build !ios

// Package mobile is the gomobile-bound iOS facade for the bidichan connect-side
// client. Its implementation is built only for iOS (GOOS=ios) and compiled into
// an XCFramework via `gomobile bind -target=ios`. On other platforms the
// package is intentionally empty so `go build ./...` / `go test ./...` at the
// module root stay green.
package mobile
