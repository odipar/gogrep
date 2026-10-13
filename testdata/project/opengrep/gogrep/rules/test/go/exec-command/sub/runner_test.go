package sub

import "os/exec"

func TestRun() { exec.Command("go", "test") }
