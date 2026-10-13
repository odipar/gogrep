package ruletest

import (
	"fmt"
	"strings"
)

// diffContext is the number of unchanged lines a diff shows around a change.
const diffContext = 3

// An edit is one line of an edit script: kept (' '), deleted ('-') or
// inserted ('+').
type edit struct {
	op   byte
	line string
}

// Diff returns a unified diff from the expected lines to the actual ones, with
// the headers "--- expected" and "+++ actual" and three lines of context, or
// "" when they are equal. As in GNU diff, an empty range in a hunk header
// starts at the line before it, but both counts are always given.
func Diff(expected, actual []string) string {
	edits := groupChanges(script(nil, expected, actual))
	// before[i] holds the numbers of expected and actual lines before edits[i].
	before := make([][2]int, len(edits)+1)
	for i, e := range edits {
		before[i+1] = before[i]
		if e.op != '+' {
			before[i+1][0]++
		}
		if e.op != '-' {
			before[i+1][1]++
		}
	}

	var b strings.Builder
	for next := 0; ; {
		change := next
		for change < len(edits) && edits[change].op == ' ' {
			change++
		}
		if change == len(edits) {
			break
		}
		// The hunk runs until the first unchanged stretch too long to bridge.
		end := change
		for {
			for end < len(edits) && edits[end].op != ' ' {
				end++
			}
			same := end
			for same < len(edits) && edits[same].op == ' ' {
				same++
			}
			if same == len(edits) || same-end > 2*diffContext {
				end = min(end+diffContext, same)
				break
			}
			end = same
		}
		start := max(next, change-diffContext)
		if b.Len() == 0 {
			b.WriteString("--- expected\n+++ actual\n")
		}
		fmt.Fprintf(&b, "@@ -%s +%s @@\n", hunkRange(before[start][0], before[end][0]), hunkRange(before[start][1], before[end][1]))
		for _, e := range edits[start:end] {
			b.WriteByte(e.op)
			b.WriteString(e.line)
			b.WriteByte('\n')
		}
		next = end
	}
	return b.String()
}

// hunkRange formats the lines from up to to (0-based, exclusive) of one side
// of a hunk: "first,count", where an empty range names the line before it.
func hunkRange(from, to int) string {
	if from == to {
		return fmt.Sprintf("%d,0", from)
	}
	return fmt.Sprintf("%d,%d", from+1, to-from)
}

// groupChanges moves the deletions of each run of changes before its
// insertions.
func groupChanges(edits []edit) []edit {
	for i := 0; i < len(edits); {
		if edits[i].op == ' ' {
			i++
			continue
		}
		j := i
		var ins []edit
		for k := i; k < len(edits) && edits[k].op != ' '; k++ {
			if edits[k].op == '-' {
				edits[j] = edits[k]
				j++
			} else {
				ins = append(ins, edits[k])
			}
		}
		i = j + copy(edits[j:], ins)
	}
	return edits
}

// script appends a shortest edit script from a to b to edits, using Myers'
// linear-space algorithm: after trimming the common prefix and suffix, it
// splits the problem at the middle snake of an optimal path.
func script(edits []edit, a, b []string) []edit {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	edits = appendEdits(edits, ' ', a[:pre])
	mid, midB := a[pre:len(a)-suf], b[pre:len(b)-suf]
	switch {
	case len(mid) == 0:
		edits = appendEdits(edits, '+', midB)
	case len(midB) == 0:
		edits = appendEdits(edits, '-', mid)
	default:
		x, y, u, v := middleSnake(mid, midB)
		edits = script(edits, mid[:x], midB[:y])
		edits = appendEdits(edits, ' ', mid[x:u])
		edits = script(edits, mid[u:], midB[v:])
	}
	return appendEdits(edits, ' ', a[len(a)-suf:])
}

func appendEdits(edits []edit, op byte, lines []string) []edit {
	for _, l := range lines {
		edits = append(edits, edit{op, l})
	}
	return edits
}

// middleSnake returns the start (x, y) and end (u, v) of the snake in the
// middle of a shortest path through the edit graph of a and b, both
// non-empty and differing in their first and in their last lines. It searches forward from
// (0, 0) and backward from (len(a), len(b)) at once until the paths overlap.
// Diagonal k holds the points with x-y = k; fwd[k] is the furthest x a
// forward path has reached on it, and bwd[k] the furthest distance from the
// end a backward path has reached on diagonal len(a)-len(b)-k.
func middleSnake(a, b []string) (int, int, int, int) {
	n, m := len(a), len(b)
	delta := n - m
	dmax := (n + m + 1) / 2
	off := dmax + 1
	fwd := make([]int, 2*off+1)
	bwd := make([]int, 2*off+1)
	for d := 0; d <= dmax; d++ {
		for k := -d; k <= d; k += 2 {
			x := fwd[off+k-1] + 1
			if k == -d || k != d && fwd[off+k-1] < fwd[off+k+1] {
				x = fwd[off+k+1]
			}
			y := x - k
			x0, y0 := x, y
			for x < n && y < m && a[x] == b[y] {
				x, y = x+1, y+1
			}
			fwd[off+k] = x
			// With delta odd, the backward paths of step d-1 can meet this one.
			if r := delta - k; delta%2 != 0 && -d < r && r < d && x+bwd[off+r] >= n {
				return x0, y0, x, y
			}
		}
		for k := -d; k <= d; k += 2 {
			x := bwd[off+k-1] + 1
			if k == -d || k != d && bwd[off+k-1] < bwd[off+k+1] {
				x = bwd[off+k+1]
			}
			y := x - k
			x0, y0 := x, y
			for x < n && y < m && a[n-1-x] == b[m-1-y] {
				x, y = x+1, y+1
			}
			bwd[off+k] = x
			// With delta even, the forward paths of step d can meet this one.
			if f := delta - k; delta%2 == 0 && -d <= f && f <= d && fwd[off+f]+x >= n {
				return n - x, m - y, n - x0, m - y0
			}
		}
	}
	panic("ruletest: no middle snake")
}
