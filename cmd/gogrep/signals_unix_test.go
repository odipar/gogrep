//go:build unix

package gogrep

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The signals a terminal sends its foreground group do not reach the opengrep
// processes, so gogrep test catches them too.
func TestTestTerminalSignals(t *testing.T) {
	useFakeOpengrep(t, 0)
	testProject(t, brokenFiles)
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGQUIT} {
		if signal.Ignored(sig) {
			continue // gogrep leaves it ignored, as under nohup
		}
		ready := filepath.Join(t.TempDir(), "ready")
		t.Setenv("GOGREP_TEST_FAKE_WAIT", ready)
		done := make(chan string, 1)
		go func() {
			code, _, stderr := runGogrep("test", testRoot+"/go/exec-command")
			done <- fmt.Sprintf("%d, %q", code, stderr)
		}()
		for _, err := os.Stat(ready); err != nil; _, err = os.Stat(ready) {
			select {
			case got := <-done:
				t.Fatalf("gogrep test = %s before opengrep ran", got)
			case <-time.After(10 * time.Millisecond):
			}
		}
		syscall.Kill(os.Getpid(), sig)
		if got, want := <-done, `130, "gogrep: interrupted\n"`; got != want {
			t.Errorf("gogrep test, sent %v = %s; want %s", sig, got, want)
		}
	}
}
