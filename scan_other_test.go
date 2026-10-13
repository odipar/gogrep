//go:build !unix

package gogrep

import "testing"

// canKill is set where the tests can check that a process is gone.
const canKill = false

func checkGone(t *testing.T, pid string) {}
