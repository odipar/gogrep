//go:build unix

package opengrep

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// killGrace is how long a cancelled process group has between SIGINT and
// SIGKILL. opengrep handles SIGINT as it does a terminal's Ctrl-C: it shows
// the cursor that its progress bar hid, and removes its temporary files.
const killGrace = time.Second

// killTree makes cmd lead a process group of its own, and cancelling its
// context interrupt that whole group with SIGINT and kill it killGrace
// later. A terminal's Ctrl-C then reaches only the caller, which must catch
// it and cancel the context. reap, called once cmd.Wait has returned, waits
// until the group is gone or killed, as it may outlive its leader.
func killTree(cmd *exec.Cmd) (reap func()) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Set by Cancel, which returns before cmd.Wait does.
	var killed chan struct{}
	var timer *time.Timer
	cmd.Cancel = func() error {
		pgid := cmd.Process.Pid
		err := syscall.Kill(-pgid, syscall.SIGINT)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		killed = make(chan struct{})
		timer = time.AfterFunc(killGrace, func() {
			syscall.Kill(-pgid, syscall.SIGKILL)
			close(killed)
		})
		return err
	}
	return func() {
		if killed == nil {
			return
		}
		for poll := time.NewTicker(10 * time.Millisecond); ; {
			if errors.Is(syscall.Kill(-cmd.Process.Pid, 0), syscall.ESRCH) && timer.Stop() {
				poll.Stop()
				return
			}
			select {
			case <-killed:
				poll.Stop()
				return
			case <-poll.C:
			}
		}
	}
}

// textBusy reports whether err is a start that failed because the
// executable was open for writing.
func textBusy(err error) bool { return errors.Is(err, syscall.ETXTBSY) }
