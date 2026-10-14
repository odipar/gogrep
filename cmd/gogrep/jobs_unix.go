//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/odipar/gogrep"
)

// passJobControl makes Ctrl-Z stop a scan's opengrep along with gogrep, and
// the SIGCONT of the shell's fg or bg continue it, while cmd runs: opengrep's
// process group is not the terminal's, so the terminal's SIGTSTP reaches
// gogrep alone. Where the kernel would not let a SIGTSTP stop gogrep (see
// stops), as when no job-control shell is there to continue it, gogrep
// ignores it, as v0.3.0 did, and the scan goes on instead of waiting for a
// SIGCONT that never comes. stop ends that. A SIGTSTP that gogrep was started
// with ignored stays ignored.
func passJobControl(cmd *gogrep.Cmd) (stop func()) {
	if signal.Ignored(syscall.SIGTSTP) {
		return func() {}
	}
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTSTP, syscall.SIGCONT)
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		for {
			select {
			case <-done:
				return
			case sig := <-sigs:
				switch {
				case sig == syscall.SIGCONT:
					cmd.Signal(syscall.SIGCONT)
				case stopsOnCtrlZ():
					// SIGSTOP, as a SIGTSTP would come back here: once
					// caught, Go never gives SIGTSTP its default action
					// back, not even after signal.Reset.
					cmd.Signal(syscall.SIGSTOP)
					syscall.Kill(os.Getpid(), syscall.SIGSTOP)
				}
			}
		}
	}()
	return func() {
		signal.Stop(sigs)
		close(done)
		<-exited
	}
}

// stopsOnCtrlZ reports whether a SIGTSTP would stop gogrep if gogrep did not
// catch it, as stops tells from gogrep's process group and session and its
// parent's.
func stopsOnCtrlZ() bool {
	ppid := os.Getppid()
	return stops(os.Getpid(), getpgid(0), getsid(0), ppid, getpgid(ppid), getsid(ppid))
}

// stops reports whether a SIGTSTP with its default action stops the process
// pid, of process group pgrp and session sid, whose parent ppid is in process
// group ppgrp and session psid; -1 is what the system cannot tell. The kernel
// discards such a SIGTSTP when the process group is orphaned: when no member
// has a parent in another process group of the same session, as a
// job-control shell is, which alone would continue the job. No signal from
// within a PID namespace stops its init, PID 1 (docker run -it), either.
//
// Only pid and its parent are looked at. pid's group is orphaned when it is
// its session leader's group, which has no job-control shell above it: pid
// leads its session (as gogrep does under ssh -t host gogrep scan ., tmux
// new 'gogrep scan .', exec gogrep or script), or its session leader runs it
// without job control, as sh -c does. So it is when pid's parent is in
// another group of another session, or outside the PID namespace (ppid 0).
// A parent in pid's group, as make is, leaves the question to a process
// further up, which in a group other than its session leader's is all but
// certainly a job-control shell's child.
func stops(pid, pgrp, sid, ppid, ppgrp, psid int) bool {
	switch {
	case pid == 1:
		return false
	case pgrp < 0 || sid < 0:
		return true // as with job control, which Ctrl-Z is for
	case pgrp == sid, ppid == 0:
		return false
	case ppgrp == pgrp:
		return true
	}
	return psid == sid
}
