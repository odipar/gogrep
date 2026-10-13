package prod

import (
	"os/exec"
	"testing"
)

func TestDeploy(t *testing.T) { exec.Command("deploy") }
