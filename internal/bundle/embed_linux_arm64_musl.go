//go:build gogrep_bundled && gogrep_musl && linux && arm64

package bundle

import _ "embed"

//go:embed bin/opengrep_linux_arm64_musl
var binary []byte

//go:embed bin/opengrep_linux_arm64_musl.sha256
var sum string
