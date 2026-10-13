package sample

import "os/exec"

func run(name string) {
	exec.Command(name, "-v")
	_ = exec.Command("ls")
}
