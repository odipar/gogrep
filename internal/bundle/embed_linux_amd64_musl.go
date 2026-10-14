//go:build gogrep_bundled && gogrep_musl && linux && amd64

package bundle

import _ "embed"

//go:embed bin/opengrep_linux_amd64_musl
var binary []byte
