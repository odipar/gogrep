//go:build unix || windows

package opengrep

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// Cancelling kills not only opengrep's launcher but also the processes it
// started, and Run returns soon after.
func TestRunKillsTree(t *testing.T) {
	t.Parallel()
	pids := filepath.Join(t.TempDir(), "pids")
	c := helperCmd(t, "tree", "GOGREP_TEST_PIDS="+pids)
	c.Stdout = new(bytes.Buffer) // a pipe that the child holds too
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runAsync(ctx, c)
	_, child := waitPids(t, pids, done)

	cancel()
	start := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run, cancelled = %v, want context.Canceled", err)
		}
		if d := time.Since(start); d > waitDelay+time.Second {
			t.Errorf("Run returned %v after the cancel, want at most %v", d, waitDelay+time.Second)
		}
	case <-time.After(waitDelay + 10*time.Second):
		t.Fatal("Run, cancelled, does not return")
	}
	for deadline := time.Now().Add(5 * time.Second); running(child); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the launcher's child %d still runs", child)
		}
	}
}
