//go:build unix

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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

// A scan's opengrep runs in a process group of its own, so the signals a
// terminal sends its foreground group reach gogrep alone, which kills
// opengrep with the processes it started, says so and exits 130.
func TestScanInterrupted(t *testing.T) {
	useFakeOpengrep(t, 0)
	t.Chdir(t.TempDir())
	t.Setenv("GOGREP_TEST_FAKE_CHILD", "1")
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			// The pass-through of an earlier test ignores SIGINT and SIGTERM
			// for good; catching a signal undoes that, and also keeps it
			// from ending the test.
			caught := make(chan os.Signal, 1)
			signal.Notify(caught, sig)
			defer signal.Stop(caught)
			ready := filepath.Join(t.TempDir(), "ready")
			t.Setenv("GOGREP_TEST_FAKE_WAIT", ready)
			done := make(chan string, 1)
			go func() {
				code, stdout, stderr := runGogrep("scan", "--config", "r.yaml", "--sarif", ".")
				done <- fmt.Sprintf("%d, %q, %q", code, stdout, stderr)
			}()
			for _, err := os.Stat(ready); err != nil; _, err = os.Stat(ready) {
				select {
				case got := <-done:
					t.Fatalf("gogrep scan = %s before opengrep ran", got)
				case <-time.After(10 * time.Millisecond):
				}
			}
			data, err := os.ReadFile(ready)
			child, _ := strconv.Atoi(string(data))
			if err != nil || child == 0 {
				t.Fatalf("the fake opengrep started no child: %q, %v", data, err)
			}
			syscall.Kill(os.Getpid(), sig)
			if got, want := <-done, `130, "", "gogrep: interrupted\n"`; got != want {
				t.Errorf("gogrep scan, sent %v = %s; want %s", sig, got, want)
			}
			for deadline := time.Now().Add(5 * time.Second); running(child); time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					syscall.Kill(child, syscall.SIGKILL)
					t.Fatalf("opengrep's child %d still runs", child)
				}
			}
		})
	}
}

// The first run of a forwarded command prepares opengrep's runtime in a
// process group of its own, which a terminal's Ctrl-C does not reach, so
// gogrep catches its interrupts meanwhile: it stops the preparation, which
// leaves nothing behind, says so and exits 130.
func TestForegroundPreparationInterrupted(t *testing.T) {
	useFakeOpengrep(t, 0)
	cache := os.Getenv("XDG_CACHE_HOME") // isolated
	for _, args := range [][]string{{"--version"}, {"opengrep", "--version"}} {
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
			t.Run(strings.Join(args, " ")+" "+sig.String(), func(t *testing.T) {
				// Undo the ignoring of an earlier pass-through, and keep
				// the signal from ending the test.
				caught := make(chan os.Signal, 1)
				signal.Notify(caught, sig)
				defer signal.Stop(caught)
				ready := filepath.Join(t.TempDir(), "ready")
				t.Setenv("GOGREP_TEST_FAKE_PREPARE_WAIT", ready)
				done := make(chan string, 1)
				go func() {
					code, stdout, stderr := runGogrep(args...)
					done <- fmt.Sprintf("%d, %q, %q", code, stdout, stderr)
				}()
				for _, err := os.Stat(ready); err != nil; _, err = os.Stat(ready) {
					select {
					case got := <-done:
						t.Fatalf("gogrep %q = %s before the preparation ran", args, got)
					case <-time.After(10 * time.Millisecond):
					}
				}
				syscall.Kill(os.Getpid(), sig)
				select {
				case got := <-done:
					if want := `130, "", "gogrep: interrupted\n"`; got != want {
						t.Errorf("gogrep %q, sent %v during the preparation = %s; want %s", args, sig, got, want)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("gogrep %q still runs after %v", args, sig)
				}
				filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
					if err == nil && strings.HasPrefix(d.Name(), ".runtime-") {
						t.Errorf("the interrupted preparation left %s", p)
					}
					return err
				})
			})
		}
	}
}

// A scan leaves the signal dispositions alone: a process started after it
// does not start with SIGINT ignored, as it did when every scan made gogrep
// ignore SIGINT and SIGTERM for good.
func TestScanLeavesSignals(t *testing.T) {
	useFakeOpengrep(t, 0)
	t.Chdir(t.TempDir())
	// Catching SIGINT undoes an earlier test's pass-through, which ignores
	// it for good; a later Ignore would undo the catch.
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, os.Interrupt)
	defer signal.Stop(caught)
	exe := os.Getenv("OPENGREP_BIN")
	probe := func() string {
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), "GOGREP_TEST_SIGPROBE=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("the probe: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := probe(); got != "false" {
		t.Fatalf("a probe started before the scan reports SIGINT ignored: %s", got)
	}
	if code, _, stderr := runGogrep("scan", "--config", "r.yaml", "."); code != 0 {
		t.Fatalf("gogrep scan = %d, %q", code, stderr)
	}
	if got := probe(); got != "false" {
		t.Errorf("a probe started after the scan reports SIGINT ignored: %s", got)
	}
}

// A scanJob is gogrep scan, run with the fake opengrep, which starts a child
// and waits until resumed.
type scanJob struct {
	cmd            *exec.Cmd // gogrep, or its parent
	done           chan struct{}
	stdout, stderr bytes.Buffer // read them once done is closed
	gogrep, child  int          // the pids of gogrep and of the fake opengrep's child
	resume         string       // the file that resumes the fake opengrep
}

// startScanJob starts gogrep scan with attr, under a parent that shares its
// process group if parent is set, as make runs a command, and with stdin,
// unless that is nil. It waits until the fake opengrep runs. The scan's
// processes are killed when the test ends.
func startScanJob(t *testing.T, attr *syscall.SysProcAttr, parent bool, stdin *os.File) *scanJob {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	j := &scanJob{done: make(chan struct{}), resume: filepath.Join(tmp, "resume")}
	ready, pid := filepath.Join(tmp, "ready"), filepath.Join(tmp, "gogrep")
	args := []string{exe, "scan", "--config", "r.yaml", "--sarif", "."}
	env := append(os.Environ(), "GOGREP_TEST_MAIN=1", "GOGREP_TEST_FAKE_WAIT="+ready, "GOGREP_TEST_FAKE_CHILD=1", "GOGREP_TEST_FAKE_RESUME="+j.resume)
	if parent {
		args = append([]string{exe}, args...)
		env = append(env, "GOGREP_TEST_PARENT="+pid)
	}
	j.cmd = exec.Command(args[0], args[1:]...)
	j.cmd.Dir, j.cmd.Env, j.cmd.SysProcAttr, j.cmd.WaitDelay = t.TempDir(), env, attr, time.Second
	if stdin != nil {
		j.cmd.Stdin = stdin
	}
	j.cmd.Stdout, j.cmd.Stderr = &j.stdout, &j.stderr
	if err := j.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		j.cmd.Wait()
		close(j.done)
	}()
	t.Cleanup(func() {
		os.WriteFile(j.resume, nil, 0o600)
		if j.child != 0 {
			syscall.Kill(j.child, syscall.SIGKILL)
		}
		syscall.Kill(-j.cmd.Process.Pid, syscall.SIGKILL) // the group it leads
		<-j.done
	})
	for deadline := time.Now().Add(10 * time.Second); j.child == 0 || j.gogrep == 0; {
		select {
		case <-j.done:
			t.Fatalf("gogrep scan exited before opengrep ran: %v, %q", j.cmd.ProcessState, j.stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake opengrep never started")
		}
		data, _ := os.ReadFile(ready)
		j.child, _ = strconv.Atoi(string(data))
		j.gogrep = j.cmd.Process.Pid
		if parent {
			data, _ := os.ReadFile(pid)
			j.gogrep, _ = strconv.Atoi(string(data))
		}
	}
	return j
}

// wait waits until the scan has ended, or fails the test.
func (j *scanJob) wait(t *testing.T) {
	t.Helper()
	select {
	case <-j.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("gogrep scan still runs, state %q, and its opengrep's child %q", state(j.gogrep), state(j.child))
	}
}

// waitState waits until the state of the process pid is stopped or not.
func waitState(t *testing.T, pid int, stopped bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); state(pid) == "T" != stopped; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d's state is %q; want stopped %v", pid, state(pid), stopped)
		}
	}
}

// Ctrl-Z stops a scan's opengrep, in its process group of its own, along
// with gogrep, and continuing gogrep continues it, where a job-control shell
// would: when gogrep is the shell's job, the leader of a process group that
// the test, standing in for the shell, is not in, and when it runs under a
// parent in that group, as make runs it. The test sends the signals to that
// group, as a terminal's Ctrl-Z and the shell's fg do.
func TestScanJobControl(t *testing.T) {
	useFakeOpengrep(t, 0)
	// gogrep inherits an ignored SIGINT, as from an earlier test's
	// pass-through, which catching it undoes.
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, os.Interrupt)
	defer signal.Stop(caught)
	for _, tt := range []struct {
		name   string
		parent bool
	}{
		{"job", false},
		{"under make", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			j := startScanJob(t, &syscall.SysProcAttr{Setpgid: true}, tt.parent, nil)
			job := j.cmd.Process.Pid
			syscall.Kill(-job, syscall.SIGTSTP)
			waitState(t, j.gogrep, true)
			waitState(t, j.child, true)
			syscall.Kill(-job, syscall.SIGCONT)
			waitState(t, j.gogrep, false)
			waitState(t, j.child, false)
			syscall.Kill(j.gogrep, syscall.SIGINT)
			j.wait(t)
			if code := j.cmd.ProcessState.ExitCode(); code != 130 || j.stderr.String() != "gogrep: interrupted\n" {
				t.Errorf("gogrep scan, interrupted after Ctrl-Z and fg = %d, %q; want exit 130", code, j.stderr.String())
			}
		})
	}
}

// Where the kernel discards a Ctrl-Z, because gogrep's process group is
// orphaned, gogrep ignores it too, as v0.3.0 did: the scan goes on and ends,
// where a stopped scan would wait for a SIGCONT that no job-control shell
// sends. The group is orphaned when gogrep leads its session, as under
// ssh -t host gogrep scan . or exec gogrep, and when it runs in its session
// leader's group, as under a non-interactive sh -c.
func TestScanOrphanedCtrlZ(t *testing.T) {
	if getsid(0) < 0 {
		t.Skip("this system does not tell sessions")
	}
	useFakeOpengrep(t, 0)
	for _, tt := range []struct {
		name        string
		parent, tty bool
	}{
		{"session leader", false, false},
		{"in its session leader's group", true, false},
		{"session leader, Ctrl-Z typed on its terminal", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attr := &syscall.SysProcAttr{Setsid: true}
			var master, tty *os.File
			if tt.tty {
				master, tty = openPty(t)
				attr.Setctty = true // Ctty 0, its stdin
			}
			j := startScanJob(t, attr, tt.parent, tty)
			if tt.tty {
				if _, err := master.Write([]byte("\x1a")); err != nil {
					t.Fatal(err)
				}
			} else {
				syscall.Kill(-j.cmd.Process.Pid, syscall.SIGTSTP) // the group it leads
			}
			time.Sleep(500 * time.Millisecond)
			for _, pid := range []int{j.gogrep, j.child} {
				if s := state(pid); s == "T" {
					t.Errorf("process %d is stopped after Ctrl-Z; want it to run on", pid)
				}
			}
			syscall.Kill(j.child, syscall.SIGKILL) // which would keep opengrep's group from ending
			if err := os.WriteFile(j.resume, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			j.wait(t)
			if code := j.cmd.ProcessState.ExitCode(); code != 0 || j.stderr.String() != "fake stderr\n" {
				t.Errorf("gogrep scan, after Ctrl-Z = %d, %q; want 0, %q", code, j.stderr.String(), "fake stderr\n")
			}
			if driver, _ := sarifRun(t, j.stdout.String()); driver != "gogrep" {
				t.Errorf("SARIF driver = %q, want gogrep", driver)
			}
		})
	}
}

// openPty opens a pseudo-terminal, and returns its master and its terminal,
// which are closed when the test ends. What is written to the terminal is
// read and dropped: a session leader that exits waits until its terminal's
// output is read (macOS). It skips the test where there is no
// pseudo-terminal.
func openPty(t *testing.T) (master, tty *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	go io.Copy(io.Discard, master)
	name, err := ptsname(master)
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("no pseudo-terminal on this system")
	}
	if err == nil {
		tty, err = os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	}
	if err != nil {
		t.Fatalf("opening the terminal of %s: %v", master.Name(), err)
	}
	t.Cleanup(func() { tty.Close() })
	return master, tty
}

// stops follows the kernel's rule for a SIGTSTP whose action is the default:
// it stops a process in a process group that a job-control shell keeps, and
// is discarded in an orphaned one.
func TestStops(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name                              string
		pid, pgrp, sid, ppid, ppgrp, psid int
		want                              bool
	}{
		{"a shell's job", 20, 20, 10, 10, 10, 10, true},
		{"under make, in a shell's job", 21, 20, 10, 20, 20, 10, true},
		{"the job of a shell in a group of its own", 30, 30, 10, 25, 25, 10, true},
		{"the job of an interactive shell that is PID 1, docker run -it image sh", 7, 7, 1, 1, 1, 1, true},
		{"session leader: ssh -t host gogrep scan ., exec gogrep", 10, 10, 10, 5, 5, 5, false},
		{"in its session leader's group, under sh -c", 11, 10, 10, 10, 10, 10, false},
		{"parent in another session", 30, 20, 10, 5, 5, 5, false},
		{"parent outside the PID namespace", 7, 6, 5, 0, -1, -1, false},
		{"parent gone", 30, 20, 10, 25, -1, -1, false},
		{"PID 1: docker run -it image gogrep scan .", 1, 1, 1, 0, -1, -1, false},
		{"no sessions on this system", 20, 20, -1, 10, -1, -1, true},
		{"PID 1, no sessions on this system", 1, -1, -1, 0, -1, -1, false},
	} {
		if got := stops(tt.pid, tt.pgrp, tt.sid, tt.ppid, tt.ppgrp, tt.psid); got != tt.want {
			t.Errorf("%s: stops(%d, %d, %d, %d, %d, %d) = %v, want %v", tt.name, tt.pid, tt.pgrp, tt.sid, tt.ppid, tt.ppgrp, tt.psid, got, tt.want)
		}
	}
}

// state returns the first letter of the state of the process pid, as ps
// prints it, such as "S", "R" or "T" (stopped); "" when there is none.
func state(pid int) string {
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		// The state follows the command name, in parentheses.
		if fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:])); len(fields) > 0 {
			return fields[0][:1]
		}
		return ""
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if s := strings.TrimSpace(string(out)); err == nil && s != "" {
		return s[:1]
	}
	return ""
}

// running reports whether the process pid runs: it exists and has not
// exited, waiting to be reaped. Linux tells from /proc, as the ps of busybox
// (Alpine) has no -p.
func running(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false
	}
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		// The state follows the command name, in parentheses.
		fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
		return len(fields) > 0 && fields[0] != "Z"
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && !strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}
