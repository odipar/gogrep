//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package main

import "syscall"

// getpgid returns the process group of the process pid, or of gogrep for 0;
// -1 when there is none.
func getpgid(pid int) int {
	pgrp, err := syscall.Getpgid(pid)
	if err != nil {
		return -1
	}
	return pgrp
}

// getsid returns the session of the process pid, or of gogrep for 0; -1 when
// there is none.
func getsid(pid int) int {
	sid, err := syscall.Getsid(pid)
	if err != nil {
		return -1
	}
	return sid
}
