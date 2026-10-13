// Package fakeopengrep is a test helper: a test binary whose TestMain runs
// Main when GOGREP_TEST_FAKE_OPENGREP=1 is set stands in for opengrep.
package fakeopengrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Main runs the fake opengrep with args, without the program name, and
// returns its exit code.
//
// It prints its args to stdout, one per line, or with --sarif a SARIF log
// from tool "opengrep" whose run's properties hold them as args, its
// working directory as dir, and the variables that $GOGREP_TEST_FAKE_ENV
// names as env, or the file $GOGREP_TEST_FAKE_SARIF names, such as a
// recorded log. The log goes to the files that -o/--output and
// --sarif-output name instead, mode 0o644, as opengrep writes them; with
// $GOGREP_TEST_FAKE_NO_SARIF=1 it writes no log. It writes
// $GOGREP_TEST_FAKE_STDERR bytes of x and a newline, if set, and "fake
// stderr" to stderr and exits with $GOGREP_TEST_FAKE_EXIT.
//
// Before that, it reports the variables that $GOGREP_TEST_FAKE_ENV, a
// comma-separated list, names on stderr as NAME=value; with
// $GOGREP_TEST_FAKE_STDIN=1 it reports up to 4 bytes of its stdin there.
// With $GOGREP_TEST_FAKE_WAIT set, it then creates that file and waits a
// minute; with $GOGREP_TEST_FAKE_CHILD=1 too, it first starts sleep 60, as
// opengrep's launcher starts opengrep-cli and opengrep-core, and writes its
// pid there.
//
// The --version run that prepares opengrep's runtime, which has a log file,
// it answers at once.
func Main(args []string) int {
	if log := filepath.Base(os.Getenv("SEMGREP_LOG_FILE")); len(args) == 1 && args[0] == "--version" &&
		(log == "log" || strings.HasPrefix(log, "opengrep-")) {
		fmt.Println("1.30.2")
		return 0
	}
	env := map[string]string{}
	if names := os.Getenv("GOGREP_TEST_FAKE_ENV"); names != "" {
		for _, name := range strings.Split(names, ",") {
			env[name] = os.Getenv(name)
			fmt.Fprintf(os.Stderr, "%s=%s\n", name, env[name])
		}
	}
	if os.Getenv("GOGREP_TEST_FAKE_STDIN") == "1" {
		in, _ := io.ReadAll(io.LimitReader(os.Stdin, 4))
		fmt.Fprintf(os.Stderr, "stdin %q\n", in)
	}
	if p := os.Getenv("GOGREP_TEST_FAKE_WAIT"); p != "" {
		var pid []byte
		if os.Getenv("GOGREP_TEST_FAKE_CHILD") == "1" {
			child := exec.Command("sleep", "60")
			child.Stdout = os.Stdout
			if err := child.Start(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			pid = strconv.AppendInt(nil, int64(child.Process.Pid), 10)
		}
		if os.WriteFile(p+".tmp", pid, 0o600) != nil || os.Rename(p+".tmp", p) != nil {
			return 2
		}
		time.Sleep(time.Minute)
	}
	files, toStdout := targets(args)
	if !slices.Contains(args, "--sarif") {
		for _, a := range args {
			fmt.Println(a)
		}
	}
	if os.Getenv("GOGREP_TEST_FAKE_NO_SARIF") != "1" {
		dir, _ := os.Getwd()
		log, _ := json.Marshal(map[string]any{
			"version": "2.1.0",
			"runs": []any{map[string]any{
				"tool":       map[string]any{"driver": map[string]any{"name": "opengrep"}},
				"properties": map[string]any{"args": args, "dir": dir, "env": env},
			}},
		})
		if f := os.Getenv("GOGREP_TEST_FAKE_SARIF"); f != "" {
			var err error
			if log, err = os.ReadFile(f); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
		}
		if toStdout {
			fmt.Printf("%s\n", log)
		}
		for _, f := range files {
			if os.WriteFile(f, log, 0o644) != nil || os.Chmod(f, 0o644) != nil {
				return 2
			}
		}
	}
	if n, err := strconv.Atoi(os.Getenv("GOGREP_TEST_FAKE_STDERR")); err == nil {
		fmt.Fprintf(os.Stderr, "%s\n", bytes.Repeat([]byte("x"), n))
	}
	fmt.Fprintln(os.Stderr, "fake stderr")
	code, _ := strconv.Atoi(os.Getenv("GOGREP_TEST_FAKE_EXIT"))
	return code
}

// targets returns where opengrep writes SARIF for args: the files, and
// whether it goes to stdout. Like opengrep, it posts nothing to a URL.
func targets(args []string) (files []string, toStdout bool) {
	var output string
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "-o" || a == "--output":
			output = next()
		case strings.HasPrefix(a, "--output="):
			output = strings.TrimPrefix(a, "--output=")
		case strings.HasPrefix(a, "-o") && !strings.HasPrefix(a, "--"):
			output = strings.TrimPrefix(strings.TrimPrefix(a, "-o"), "=")
		case a == "--sarif-output":
			files = append(files, next())
		case strings.HasPrefix(a, "--sarif-output="):
			files = append(files, strings.TrimPrefix(a, "--sarif-output="))
		}
	}
	if slices.Contains(args, "--sarif") {
		if output == "" {
			toStdout = true
		} else {
			files = append(files, output)
		}
	}
	files = slices.DeleteFunc(files, func(f string) bool {
		return f == "" || strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://")
	})
	return files, toStdout
}
