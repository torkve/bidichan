//go:build !ios && !android

// Package mobile is the gomobile-bound mobile facade for the bidichan
// connect-side client. Its implementation is built only for the mobile
// platforms — GOOS=ios, compiled into an XCFramework via
// `gomobile bind -target=ios`, and GOOS=android, compiled into an AAR via
// `gomobile bind -target=android`. On other platforms the package is
// intentionally empty so `go build ./...` / `go test ./...` at the module root
// stay green.
package mobile
