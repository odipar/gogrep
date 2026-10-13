package ruletest

import (
	"bytes"
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// Render renders a fixture's SARIF log as its expected table: a row per
// result, "| path:startLine:startColumn:endLine:endColumn | message |", then,
// under a #select and a diagnostics header, a row per notification below
// error level, "| level | id | message |". samples are the fixture's sample
// paths, which notification messages name. It is an error when a result
// cannot be placed in a sample: it has no location, an incomplete region, or
// a uri outside the fixture.
func Render(log *Log, samples []string) ([]byte, error) {
	type row struct {
		path, msg  string
		start, end [2]int
	}
	var rows []row
	var diags []string
	for _, run := range log.Runs {
		for i, res := range run.Results {
			if len(res.Locations) == 0 {
				return nil, fmt.Errorf("result %d has no location", i+1)
			}
			loc := res.Locations[0].PhysicalLocation
			uri, reg := loc.ArtifactLocation.URI, loc.Region
			p, ok := fixturePath(uri)
			if !ok {
				return nil, fmt.Errorf("result %d has uri %q, which is not a path in the fixture", i+1, uri)
			}
			if min(reg.StartLine, reg.StartColumn, reg.EndLine, reg.EndColumn) < 1 {
				return nil, fmt.Errorf("result %d in %s has an incomplete region %d:%d:%d:%d",
					i+1, p, reg.StartLine, reg.StartColumn, reg.EndLine, reg.EndColumn)
			}
			rows = append(rows, row{
				path:  p,
				msg:   crlfToLF(res.Message.Text),
				start: [2]int{reg.StartLine, reg.StartColumn},
				end:   [2]int{reg.EndLine, reg.EndColumn},
			})
		}
		for _, inv := range run.Invocations {
			for _, n := range inv.ToolExecutionNotifications {
				level := cmp.Or(n.Level, "warning")
				if level == "error" {
					continue
				}
				msg := slashPaths(n.Message.Text, samples, filepath.Separator)
				diags = append(diags, "| "+escape(level)+" | "+escape(n.Descriptor.ID)+" | "+escape(msg)+" |")
			}
		}
	}

	slices.SortFunc(rows, func(a, b row) int {
		return cmp.Or(
			strings.Compare(a.path, b.path),
			slices.Compare(a.start[:], b.start[:]),
			slices.Compare(a.end[:], b.end[:]),
			strings.Compare(a.msg, b.msg),
		)
	})
	slices.Sort(diags)

	var b bytes.Buffer
	if len(diags) > 0 {
		b.WriteString("#select\n")
	}
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s:%d:%d:%d:%d | %s |\n", escape(r.path), r.start[0], r.start[1], r.end[0], r.end[1], escape(r.msg))
	}
	if len(diags) > 0 {
		b.WriteString("diagnostics\n")
		for _, d := range diags {
			b.WriteString(d + "\n")
		}
	}
	return b.Bytes(), nil
}

// Normalize returns the lines of an expected table as they are compared:
// without a UTF-8 BOM, with CRLF read as LF, and without trailing empty
// lines, so a missing final newline does not matter.
func Normalize(data []byte) []string {
	s := crlfToLF(strings.TrimPrefix(string(data), "\uFEFF"))
	lines := strings.Split(s, "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// fixturePath returns a result uri as a slash path relative to the fixture
// directory, opengrep's working directory. It never percent-decodes. It
// reports false for a uri that is empty, absolute, outside the directory, or
// a URL.
func fixturePath(uri string) (string, bool) {
	p := strings.TrimPrefix(strings.ReplaceAll(uri, `\`, "/"), "./")
	switch {
	case p == "", p == "..", strings.HasPrefix(p, "../"), strings.Contains(p, "://"):
		return "", false
	case strings.HasPrefix(p, "/"), len(p) >= 3 && p[1] == ':' && p[2] == '/': // also C:\
		return "", false
	}
	return p, true
}

// slashPaths replaces each sample's native path in a notification message,
// with or without a leading "."+sep, by the sample's slash path, so that
// messages read the same on every OS. sep is the OS path separator; with '/'
// messages already name samples by their slash paths.
func slashPaths(msg string, samples []string, sep byte) string {
	if sep == '/' {
		return msg
	}
	var pairs [][2]string
	for _, s := range samples {
		native := strings.ReplaceAll(s, "/", string(sep))
		pairs = append(pairs, [2]string{"." + string(sep) + native, s})
		if native != s {
			pairs = append(pairs, [2]string{native, s})
		}
	}
	// The replacer tries its pairs in order at each position: longest first.
	slices.SortStableFunc(pairs, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	var oldnew []string
	for _, p := range pairs {
		oldnew = append(oldnew, p[0], p[1])
	}
	return strings.NewReplacer(oldnew...).Replace(msg)
}

// escape returns s as a table cell. CRLF becomes LF; then \ and | are
// escaped with a backslash, LF, CR and TAB become \n, \r and \t, other
// control characters \u00XX, and bytes that are not UTF-8 \xHH.
func escape(s string) string {
	s = crlfToLF(s)
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02X`, s[i])
		case r == '\\' || r == '|':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func crlfToLF(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }
