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
// there is none. Package syscall has no Getsid on Linux.
func getsid(pid int) int {
	sid, _, errno := syscall.RawSyscall(syscall.SYS_GETSID, uintptr(pid), 0, 0)
	if errno != 0 {
		return -1
	}
	return int(sid)
}
