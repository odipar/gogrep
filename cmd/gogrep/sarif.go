package gogrep

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/ruletest"
)

// toolName replaces opengrep's tool.driver.name in SARIF output, so GitHub
// code scanning lists the results under gogrep.
const toolName = "gogrep"

// sarifTargets reports where opengrep will write SARIF for args: the files it
// writes to, and whether SARIF goes to stdout.
func sarifTargets(args []string) (files []string, toStdout bool) {
	sarif := slices.Contains(args, "--sarif")
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
	if sarif {
		if output == "" {
			toStdout = true
		} else {
			files = append(files, output)
		}
	}
	// Results posted to a URL never reach a local file.
	files = slices.DeleteFunc(files, func(f string) bool {
		return f == "" || strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://")
	})
	return files, toStdout
}

// rebrandFile rewrites the SARIF file at path in place with rebrand, and
// makes it readable by its owner only: opengrep creates it 0o644, and
// os.WriteFile keeps the mode of a file that exists. valid reports whether
// the file held the SARIF 2.1.0 log of one run that gogrep asks for.
func rebrandFile(path string) (valid bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	_, err = ruletest.DecodeSARIF(data)
	valid = err == nil
	out, err := rebrand(data)
	if err != nil {
		return valid, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return valid, err
	}
	return valid, os.Chmod(path, 0o600)
}

// rebrand sets tool.driver.name to toolName in every run of a SARIF log,
// leaving all other fields untouched.
func rebrand(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var log map[string]any
	if err := dec.Decode(&log); err != nil {
		return nil, err
	}
	runs, _ := log["runs"].([]any)
	for _, r := range runs {
		run, _ := r.(map[string]any)
		tool, _ := run["tool"].(map[string]any)
		if driver, ok := tool["driver"].(map[string]any); ok {
			driver["name"] = toolName
		}
	}
	return json.Marshal(log)
}
