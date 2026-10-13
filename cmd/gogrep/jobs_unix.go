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
// gogrep alone. stop ends that. A SIGTSTP that gogrep was started with
// ignored stays ignored.
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
				if sig == syscall.SIGTSTP {
					// SIGSTOP: a SIGTSTP would come back here.
					cmd.Signal(syscall.SIGSTOP)
					syscall.Kill(os.Getpid(), syscall.SIGSTOP)
				} else {
					cmd.Signal(syscall.SIGCONT)
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
