// Package bundle holds the opengrep executable embedded in gogrep builds made
// with -tags gogrep_bundled (plus gogrep_musl for the Alpine variant on
// Linux). Run `go run ./tools/fetch-opengrep` first to download it.
package bundle

// Binary returns the embedded opengrep executable, or nil when the build
// embeds none: without -tags gogrep_bundled, or on a platform that
// opengrep.json pins no opengrep for. Its SHA-256 is the one opengrep.json
// pins.
func Binary() []byte {
	return binary
}
