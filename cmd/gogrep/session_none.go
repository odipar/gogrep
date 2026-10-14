//go:build unix && !(linux || darwin || dragonfly || freebsd || netbsd || openbsd)

package main

// getpgid and getsid return -1, unknown: package syscall has neither Getpgid
// nor Getsid on this system.
func getpgid(int) int { return -1 }
func getsid(int) int  { return -1 }
