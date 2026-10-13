//go:build gogrep_bundled

package bundle

import _ "embed"

//go:embed bin/opengrep_darwin_arm64
var binary []byte
