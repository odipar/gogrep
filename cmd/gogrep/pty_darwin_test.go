package main

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"
)

// ptsname grants and unlocks the pseudo-terminal whose master is master, and
// returns the name of its terminal.
func ptsname(master *os.File) (string, error) {
	var name [128]byte // TIOCPTYGNAME's size
	for _, req := range []uintptr{syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
		if err := ioctl(master, req, nil); err != nil {
			return "", err
		}
	}
	if err := ioctl(master, syscall.TIOCPTYGNAME, unsafe.Pointer(&name)); err != nil {
		return "", err
	}
	n, _, _ := bytes.Cut(name[:], []byte{0})
	return string(n), nil
}

// ioctl makes the ioctl call req with arg on f.
func ioctl(f *os.File, req uintptr, arg unsafe.Pointer) error {
	c, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var errno syscall.Errno
	if err := c.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg))
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}
