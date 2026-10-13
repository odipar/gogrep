//go:build !unix && !windows

package opengrep

// running reports whether the process pid runs, which these tests cannot
// tell here.
func running(int) bool { return false }
