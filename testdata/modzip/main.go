// Command modzip files a commit of gogrep in a GOPROXY directory tree, as
// the module zip, go.mod and .info that the go command downloads, and
// prints the pseudo-version it is filed under. CI then runs `go get` of that
// version with GOPROXY=file://<dir>, which tests what a consumer of an
// untagged commit gets: exactly the files of the module zip.
//
// Usage:
//
//	go run . -repo ../.. -out "$RUNNER_TEMP/proxy" [-rev HEAD]
//
// It is a module of its own, so that gogrep's module needs no dependency
// beyond gopkg.in/yaml.v3 and its zip leaves this directory out.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/zip"
)

const modulePath = "github.com/odipar/gogrep"

func main() {
	repo := flag.String("repo", "../..", "the gogrep git `checkout`")
	out := flag.String("out", "", "the GOPROXY `directory` to write into")
	rev := flag.String("rev", "HEAD", "the git `revision` to file")
	flag.Parse()
	if *out == "" || flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	v, err := run(*repo, *out, *rev)
	if err != nil {
		fmt.Fprintln(os.Stderr, "modzip:", err)
		os.Exit(1)
	}
	fmt.Println(v)
}

// run files rev of the repository repo in the proxy tree out and returns its
// pseudo-version.
func run(repo, out, rev string) (string, error) {
	repo, err := filepath.Abs(repo)
	if err != nil {
		return "", err
	}
	gitOut := func(args ...string) ([]byte, error) {
		b, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
		if ee, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, ee.Stderr)
		}
		return b, err
	}
	git := func(args ...string) (string, error) {
		b, err := gitOut(args...)
		return strings.TrimSpace(string(b)), err
	}
	hash, err := git("rev-parse", "--verify", rev+"^{commit}")
	if err != nil {
		return "", err
	}
	secs, err := git("log", "-1", "--format=%ct", hash)
	if err != nil {
		return "", err
	}
	unix, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {
		return "", fmt.Errorf("commit time %q: %v", secs, err)
	}
	t := time.Unix(unix, 0).UTC()
	// The latest release tag before the commit, if the clone has tags.
	older, _ := git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", hash)
	if !semver.IsValid(older) || semver.Build(older) != "" {
		older = ""
	}
	v := module.PseudoVersion("v0", older, t, hash[:12])

	gomod, err := gitOut("show", hash+":go.mod")
	if err != nil {
		return "", err
	}
	if p := modfile.ModulePath(gomod); p != modulePath {
		return "", fmt.Errorf("go.mod of %s is module %q, want %s", hash, p, modulePath)
	}

	esc, err := module.EscapePath(modulePath)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(out, filepath.FromSlash(esc), "@v")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(filepath.Join(dir, v+".zip"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	err = zip.CreateFromVCS(f, module.Version{Path: modulePath, Version: v}, repo, hash, "")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("module zip: %w", err)
	}
	info, err := json.Marshal(struct {
		Version string
		Time    time.Time
	}{v, t})
	if err != nil {
		return "", err
	}
	for name, data := range map[string][]byte{v + ".mod": gomod, v + ".info": info, "list": []byte(v + "\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return "", err
		}
	}
	return v, nil
}
