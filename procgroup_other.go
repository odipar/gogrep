//go:build !unix && !windows

package main

import "os/exec"

// killTree leaves cmd as it is, so cancelling its context kills cmd alone.
// opengrep ships only for Linux, macOS and Windows; this keeps gogrep
// building for other systems.
func killTree(*exec.Cmd) {}
