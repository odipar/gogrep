//go:build gogrep_bundled

package bundle

import _ "embed"

//go:embed bin/opengrep_windows_amd64
var binary []byte

//go:embed bin/opengrep_windows_amd64.sha256
var sum string
