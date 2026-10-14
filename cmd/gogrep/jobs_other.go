//go:build !unix

package main

import "github.com/odipar/gogrep"

// passJobControl does nothing: this system has no job control.
func passJobControl(*gogrep.Cmd) (stop func()) { return func() {} }
