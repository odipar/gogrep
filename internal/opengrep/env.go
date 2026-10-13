package opengrep

import (
	"runtime"
	"slices"
	"strings"
)

// UTF8Env returns env with a UTF-8 locale for opengrep: without one, its
// embedded Python reads rule files as ASCII and crashes on non-ASCII rules.
// On Windows it adds PYTHONUTF8=1. Elsewhere it adds LC_ALL=C.UTF-8 unless
// env already selects a UTF-8 locale, through the first of LC_ALL, LC_CTYPE
// and LANG that env sets to a value; as os/exec passes on only the last
// entry for a name, that is the one read. env itself is never changed.
func UTF8Env(env []string) []string {
	if runtime.GOOS == "windows" {
		return append(slices.Clip(env), "PYTHONUTF8=1")
	}
	locale := ""
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := lookup(env, name); v != "" {
			locale = v
			break
		}
	}
	if l := strings.ToLower(locale); strings.Contains(l, "utf-8") || strings.Contains(l, "utf8") {
		return env
	}
	return append(slices.Clip(env), "LC_ALL=C.UTF-8")
}

// HermeticEnv returns env without the SEMGREP_* and OPENGREP_* variables,
// which change what opengrep scans, where it logs, and whether it uses the
// network. On Windows, where names ignore case, so does the match. env
// itself is never changed.
func HermeticEnv(env []string) []string {
	out := []string{} // not nil, which would make os/exec pass the process's environment
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if runtime.GOOS == "windows" {
			name = strings.ToUpper(name)
		}
		if !strings.HasPrefix(name, "SEMGREP_") && !strings.HasPrefix(name, "OPENGREP_") {
			out = append(out, kv)
		}
	}
	return out
}

// lookup returns the value of the last entry for name in env.
func lookup(env []string, name string) string {
	for _, kv := range slices.Backward(env) {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}
