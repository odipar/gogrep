//go:build bundled && !gogrep_bundled

package bundle

// The build tags bundled and musl are now gogrep_bundled and gogrep_musl, so
// that a tag set for another reason cannot switch on embeds. Building with the
// old tag fails here rather than quietly embedding nothing.
var _ = build_with_tags_gogrep_bundled_not_bundled
