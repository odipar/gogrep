package opengrep

import (
	"runtime"
	"slices"
	"testing"
)

func TestUTF8Env(t *testing.T) {
	// The process's own locale does not count, only env's.
	t.Setenv("LC_ALL", "C")
	t.Setenv("LANG", "en_US.UTF-8")
	if runtime.GOOS == "windows" {
		env := []string{"LANG=en_US.UTF-8"}
		if got, want := UTF8Env(env), []string{"LANG=en_US.UTF-8", "PYTHONUTF8=1"}; !slices.Equal(got, want) {
			t.Errorf("UTF8Env(%q) = %q, want %q", env, got, want)
		}
		return
	}
	tests := []struct {
		env []string
		add bool // whether LC_ALL=C.UTF-8 is added
	}{
		{nil, true},
		{[]string{"PATH=/bin"}, true},
		{[]string{"LANG=en_US.UTF-8"}, false},
		{[]string{"LC_CTYPE=C.utf8"}, false},
		{[]string{"LC_ALL=C", "LANG=en_US.UTF-8"}, true},         // LC_ALL comes first
		{[]string{"LC_ALL=", "LC_CTYPE=en_US.UTF-8"}, false},     // an empty value does not count
		{[]string{"LANG=C", "LANG=en_US.UTF-8"}, false},          // the last entry counts
		{[]string{"LANG=en_US.UTF-8", "LANG=POSIX"}, true},       // the last entry counts
		{[]string{"lang=en_US.UTF-8", "LC_ALL_X=C.UTF-8"}, true}, // other names
	}
	for _, tt := range tests {
		want := tt.env
		if tt.add {
			want = append(slices.Clone(tt.env), "LC_ALL=C.UTF-8")
		}
		if got := UTF8Env(tt.env); !slices.Equal(got, want) {
			t.Errorf("UTF8Env(%q) = %q, want %q", tt.env, got, want)
		}
	}

	// env is never written to, even with room to spare.
	env := make([]string, 1, 4)
	env[0] = "PATH=/bin"
	got := UTF8Env(env)
	_ = append(env, "OTHER=1")
	if want := []string{"PATH=/bin", "LC_ALL=C.UTF-8"}; !slices.Equal(got, want) {
		t.Errorf("UTF8Env(%q) = %q after the caller appended to its env, want %q", env, got, want)
	}
}

func TestHermeticEnv(t *testing.T) {
	t.Parallel()
	env := []string{"PATH=/bin", "SEMGREP_RULES=r.yaml", "OPENGREP_BIN=/x", "SEMGREPX=1", "HOME=/h", "OPENGREP_ENABLE_VERSION_CHECK=1", "=C:=C:\\"}
	before := slices.Clone(env)
	want := []string{"PATH=/bin", "SEMGREPX=1", "HOME=/h", "=C:=C:\\"}
	if got := HermeticEnv(env); !slices.Equal(got, want) {
		t.Errorf("HermeticEnv(%q) = %q, want %q", env, got, want)
	}
	if !slices.Equal(env, before) {
		t.Errorf("HermeticEnv changed its argument to %q", env)
	}
	// An empty environment stays empty, rather than becoming nil, which
	// os/exec would replace with the process's environment.
	if got := HermeticEnv([]string{"SEMGREP_RULES=r.yaml"}); got == nil || len(got) != 0 {
		t.Errorf("HermeticEnv of only SEMGREP_RULES = %#v, want an empty, non-nil slice", got)
	}
	lower := []string{"semgrep_rules=r.yaml"}
	want = lower
	if runtime.GOOS == "windows" {
		want = []string{}
	}
	if got := HermeticEnv(lower); !slices.Equal(got, want) {
		t.Errorf("HermeticEnv(%q) = %q, want %q", lower, got, want)
	}
}
