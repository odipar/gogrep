//go:build !unix && !windows

package opengrep

import "os/exec"

// killTree leaves cmd as it is, so cancelling its context kills cmd alone.
// opengrep ships only for Linux, macOS and Windows; this keeps gogrep
// building for other systems.
func killTree(*exec.Cmd) {}

// textBusy reports whether err is a start that failed because the
// executable was open for writing.
func textBusy(error) bool { return false }
