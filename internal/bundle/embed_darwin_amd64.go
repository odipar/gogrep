//go:build gogrep_bundled

package bundle

import _ "embed"

//go:embed bin/opengrep_darwin_amd64
var binary []byte
