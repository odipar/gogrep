//go:build bundled

package bundle

import _ "embed"

//go:embed bin/opengrep_linux_arm64
var binary []byte

//go:embed bin/opengrep_linux_arm64.sha256
var sum string
