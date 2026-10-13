//go:build gogrep_bundled

package bundle

import "embed"

//go:embed bin/rules/*.tar.gz
var ruleArchives embed.FS
