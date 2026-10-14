package ruletest

import (
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// lines returns the numbers from to to as lines.
func lines(from, to int) []string {
	var ls []string
	for i := from; i <= to; i++ {
		ls = append(ls, strconv.Itoa(i))
	}
	return ls
}

func TestDiff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		expected, actual []string
		want             string
	}{
		{"equal", lines(1, 5), lines(1, 5), ""},
		{"both empty", nil, nil, ""},
		// The design's regression example (§2.4).
		{"narrowed pattern",
			[]string{
				`| sample.go:6:2:6:26 | Avoid running name with exec.Command |`,
				`| sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |`,
				`| sub/runner_test.go:5:18:5:44 | Avoid running "go" with exec.Command |`,
			},
			[]string{`| sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |`},
			`--- expected
+++ actual
@@ -1,3 +1,1 @@
-| sample.go:6:2:6:26 | Avoid running name with exec.Command |
 | sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |
-| sub/runner_test.go:5:18:5:44 | Avoid running "go" with exec.Command |
`},
		{"changed line",
			[]string{
				`| a.go:5:2:5:20 | Avoid running "ls" with exec.Command |`,
				`| a.go:6:2:6:24 | Avoid running cmd with exec.Command |`,
			},
			[]string{
				`| a.go:5:2:5:20 | Avoid running "ls" with exec.Command |`,
				`| a.go:6:2:6:30 | Avoid running cmd with exec.Command |`,
			},
			`--- expected
+++ actual
@@ -1,2 +1,2 @@
 | a.go:5:2:5:20 | Avoid running "ls" with exec.Command |
-| a.go:6:2:6:24 | Avoid running cmd with exec.Command |
+| a.go:6:2:6:30 | Avoid running cmd with exec.Command |
`},
		{"empty expected", nil, []string{"| pod.yaml:7:9:7:25 | Container runs privileged |"},
			"--- expected\n+++ actual\n@@ -0,0 +1,1 @@\n+| pod.yaml:7:9:7:25 | Container runs privileged |\n"},
		{"empty actual", []string{"a", "b"}, nil,
			"--- expected\n+++ actual\n@@ -1,2 +0,0 @@\n-a\n-b\n"},
		{"insert with context", lines(1, 10), slices.Concat(lines(1, 5), []string{"x"}, lines(6, 10)),
			"--- expected\n+++ actual\n@@ -3,6 +3,7 @@\n 3\n 4\n 5\n+x\n 6\n 7\n 8\n"},
		{"delete at the start", lines(1, 10), lines(2, 10),
			"--- expected\n+++ actual\n@@ -1,4 +1,3 @@\n-1\n 2\n 3\n 4\n"},
		{"delete at the end", lines(1, 10), lines(1, 9),
			"--- expected\n+++ actual\n@@ -7,4 +7,3 @@\n 7\n 8\n 9\n-10\n"},
		{"deletions before insertions", []string{"1", "2", "3"}, []string{"4", "5", "6"},
			"--- expected\n+++ actual\n@@ -1,3 +1,3 @@\n-1\n-2\n-3\n+4\n+5\n+6\n"},
		{"changes six lines apart share a hunk",
			lines(1, 9), slices.Concat([]string{"a"}, lines(2, 7), []string{"b"}, lines(9, 9)),
			"--- expected\n+++ actual\n@@ -1,9 +1,9 @@\n-1\n+a\n 2\n 3\n 4\n 5\n 6\n 7\n-8\n+b\n 9\n"},
		{"changes seven lines apart get two hunks",
			lines(1, 10), slices.Concat([]string{"a"}, lines(2, 8), []string{"b"}, lines(10, 10)),
			"--- expected\n+++ actual\n@@ -1,4 +1,4 @@\n-1\n+a\n 2\n 3\n 4\n@@ -6,5 +6,5 @@\n 6\n 7\n 8\n-9\n+b\n 10\n"},
		{"empty lines", []string{"", "a"}, []string{"", "", "a"},
			"--- expected\n+++ actual\n@@ -1,2 +1,3 @@\n \n+\n a\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Diff(tt.expected, tt.actual); got != tt.want {
				t.Errorf("Diff(%q, %q) =\n%s\nwant\n%s", tt.expected, tt.actual, got, tt.want)
			}
		})
	}
}

// TestScriptShortest checks on random inputs that the edit script turns a
// into b and keeps a longest common subsequence.
func TestScriptShortest(t *testing.T) {
	t.Parallel()
	rnd := rand.New(rand.NewPCG(1, 2))
	random := func() []string {
		s := make([]string, rnd.IntN(13))
		for i := range s {
			s[i] = string(rune('a' + rnd.IntN(3)))
		}
		return s
	}
	for range 5000 {
		a, b := random(), random()
		var gotA, gotB []string
		kept := 0
		for _, e := range groupChanges(script(nil, a, b)) {
			if e.op != '+' {
				gotA = append(gotA, e.line)
			}
			if e.op != '-' {
				gotB = append(gotB, e.line)
			}
			if e.op == ' ' {
				kept++
			}
		}
		if !slices.Equal(gotA, a) || !slices.Equal(gotB, b) || kept != lcs(a, b) {
			t.Fatalf("script(%q, %q) gives %q and %q keeping %d lines; want a, b, %d",
				a, b, gotA, gotB, kept, lcs(a, b))
		}
	}
}

// lcs returns the length of a longest common subsequence of a and b.
func lcs(a, b []string) int {
	prev, cur := make([]int, len(b)+1), make([]int, len(b)+1)
	for i := range a {
		for j := range b {
			if a[i] == b[j] {
				cur[j+1] = prev[j] + 1
			} else {
				cur[j+1] = max(prev[j+1], cur[j])
			}
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func TestDiffLarge(t *testing.T) {
	t.Parallel()
	a := strings.Split(strings.Repeat("a\n", 3000)+strings.Repeat("b\n", 3000), "\n")
	b := strings.Split(strings.Repeat("c\n", 3000)+strings.Repeat("b\n", 3000), "\n")
	got := Diff(a, b)
	if want := "--- expected\n+++ actual\n@@ -1,3003 +1,3003 @@\n"; !strings.HasPrefix(got, want) || strings.Count(got, "\n") != 2+1+3000+3000+3 {
		t.Errorf("Diff of 6000 lines starts %q and has %d lines", got[:min(len(got), 60)], strings.Count(got, "\n"))
	}
}
