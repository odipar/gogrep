//go:build !gogrep_bundled

package bundle

import "embed"

var (
	binary       []byte
	sum          string
	ruleArchives embed.FS
)
