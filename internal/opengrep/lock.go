package opengrep

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// lockPoll is how often a wait for a lock tries again.
const lockPoll = 100 * time.Millisecond

// lock takes the exclusive lock on the file path, which it creates 0o600 in
// a directory created 0o700, trying every lockPoll until it has the lock or
// ctx is done. unlock releases the lock. The operating system releases it
// when the process dies, so no lock outlives its holder. Where the file
// system cannot lock, lock returns that error and an unlock that does
// nothing: a lock only avoids duplicate work.
func lock(ctx context.Context, path string) (unlock func(), err error) {
	nothing := func() {}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nothing, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nothing, err
	}
	for {
		locked, err := tryLock(f)
		switch {
		case locked:
			return func() {
				unlockFile(f)
				f.Close()
			}, nil
		case err != nil:
			f.Close()
			return nothing, err
		}
		t := time.NewTimer(lockPoll)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			f.Close()
			return nothing, ctx.Err()
		}
	}
}
