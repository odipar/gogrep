//go:build unix && !linux && !darwin

package main

import (
	"errors"
	"os"
)

// ptsname is not implemented here.
func ptsname(*os.File) (string, error) { return "", errors.ErrUnsupported }
