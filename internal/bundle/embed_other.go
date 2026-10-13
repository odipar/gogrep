//go:build gogrep_bundled && !(darwin && (amd64 || arm64)) && !(linux && (amd64 || arm64)) && !(windows && amd64)

package bundle

// opengrep.json pins no opengrep for this platform, so a bundled build embeds
// none and runs the opengrep on $PATH, as an unbundled one does.
var (
	binary []byte
	sum    string
)
