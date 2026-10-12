//go:build bundled && !musl

package bundle

import _ "embed"

//go:embed bin/opengrep_linux_amd64
var binary []byte

//go:embed bin/opengrep_linux_amd64.sha256
var sum string
