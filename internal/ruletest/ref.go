package ruletest

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/rules"
)

// maxSuggestions caps the "did you mean" list of an unresolved reference.
const maxSuggestions = 5

// ParseRef returns the rule reference in a rule.ref file: its only line that
// is neither blank nor a # comment, trimmed. A leading UTF-8 BOM is ignored
// and CRLF line ends are accepted.
func ParseRef(data []byte) (string, error) {
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))
	var refs []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.Contains(line, ": "):
			return "", fmt.Errorf("unsupported option %q in rule.ref", line)
		}
		refs = append(refs, line)
	}
	switch {
	case len(refs) == 0:
		return "", errors.New("rule.ref is empty")
	case len(refs) > 1:
		return "", fmt.Errorf("rule.ref has %d references; a fixture tests exactly one rule", len(refs))
	case len(refs[0]) >= 2 && strings.HasPrefix(refs[0], "/") && strings.HasSuffix(refs[0], "/"):
		return "", errors.New("a fixture must name one rule, not a /regex/")
	}
	return refs[0], nil
}

// Resolve returns the rule that ref names for a fixture in namespace, a
// slash path such as go/net: the one rule among all whose qualified id is
// ref, project.<namespace>.<ref> (with dots for the namespace's slashes) or
// project.<ref>. Ids compare exactly, never as suffixes. When no rule
// matches, the error suggests the rules whose id ends in .<ref>, and notes
// when all holds no bundled rules (rules outside the project and gogrep sets).
func Resolve(ref, namespace string, all []*rules.Rule) (*rules.Rule, error) {
	ids := []string{ref, "project." + ref}
	if namespace != "" {
		ids = append(ids, "project."+strings.ReplaceAll(namespace, "/", ".")+"."+ref)
	}
	var found []string
	var rule *rules.Rule
	for _, r := range all {
		if slices.Contains(ids, r.ID) {
			found, rule = append(found, r.ID), r
		}
	}
	switch {
	case len(found) == 1:
		return rule, nil
	case len(found) > 1:
		slices.Sort(found)
		return nil, fmt.Errorf("rule reference %q is ambiguous: %s; write the full id", ref, strings.Join(found, ", "))
	}

	msg := fmt.Sprintf("rule reference %q matches no rule", ref)
	var near []string
	suffix := "." + strings.ToLower(ref)
	bundled := false
	for _, r := range all {
		if strings.HasSuffix(strings.ToLower(r.ID), suffix) {
			near = append(near, r.ID)
		}
		if r.Set != "project" && r.Set != "gogrep" {
			bundled = true
		}
	}
	if len(near) > 0 {
		slices.Sort(near)
		msg += "; did you mean " + strings.Join(near[:min(len(near), maxSuggestions)], ", ") + "?"
	}
	msg += fmt.Sprintf("; list candidates with: gogrep rules --rule '/%s/'", ref)
	if !bundled {
		msg += "; this gogrep build has no bundled rule sets"
	}
	return nil, errors.New(msg)
}
