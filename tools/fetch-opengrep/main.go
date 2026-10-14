// Command fetch-opengrep downloads the opengrep binaries pinned in
// opengrep.json into internal/bundle/bin, verifying each SHA-256, so that
// gogrep can be built with -tags gogrep_bundled. It also keeps the rule set
// archives committed in internal/rulesets in step with opengrep.json: a rule
// set whose stamp is not its pin's is fetched at the pinned git commit,
// verified and packed again, for you to commit. With -check-rules, it only
// checks that each committed archive holds what its pinned commit does.
//
// Usage:
//
//	go run ./tools/fetch-opengrep                  # current platform
//	go run ./tools/fetch-opengrep all              # every platform in the config
//	go run ./tools/fetch-opengrep linux/amd64 ...  # specific platforms
//	go run ./tools/fetch-opengrep linux/amd64/musl # musl (Alpine) variant
//	go run ./tools/fetch-opengrep -pin v1.31.0     # re-pin the config to another release
//	go run ./tools/fetch-opengrep -check-rules     # check the committed rule set archives
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/pin"
)

const (
	repo     = "opengrep/opengrep"
	outDir   = "internal/bundle/bin"
	rulesDir = "internal/rulesets"
)

func main() {
	configPath := flag.String("config", "opengrep.json", "pin config `file`")
	tag := flag.String("pin", "", "re-pin the config to this opengrep release `tag` and exit")
	check := flag.Bool("check-rules", false, "fetch each pinned rule set again, check that its committed archive holds the same files, and exit")
	flag.Parse()

	var err error
	if *check {
		err = checkAll(*configPath)
	} else {
		err = run(*configPath, *tag, flag.Args())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch-opengrep: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, tag string, platforms []string) error {
	cfg, err := readConfig(configPath)
	if err != nil {
		return err
	}
	if tag != "" {
		return repin(configPath, cfg, tag)
	}

	switch {
	case len(platforms) == 0:
		platforms = []string{runtime.GOOS + "/" + runtime.GOARCH}
	case len(platforms) == 1 && platforms[0] == "all":
		platforms = slices.Sorted(maps.Keys(cfg.Assets))
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	for _, p := range platforms {
		a, ok := cfg.Assets[p]
		if !ok {
			return fmt.Errorf("no opengrep asset pinned for %s in %s", p, configPath)
		}
		if err := fetch(cfg.Version, p, a); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	for _, r := range cfg.Rules {
		if err := fetchRules(r); err != nil {
			return fmt.Errorf("rules %s: %w", r.Name, err)
		}
	}
	return nil
}

// checkAll checks every rule set that the config at configPath pins.
func checkAll(configPath string) error {
	cfg, err := readConfig(configPath)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range cfg.Rules {
		if err := checkRules(r); err != nil {
			errs = append(errs, fmt.Errorf("rules %s: %w", r.Name, err))
		}
	}
	return errors.Join(errs...)
}

func readConfig(path string) (*pin.Pins, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := pin.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// fetch downloads asset a into outDir as opengrep_<os>_<arch>[_<variant>],
// verified as gogrep install-opengrep verifies it. A file already present
// with the pinned checksum is kept.
func fetch(version, platform string, a pin.Asset) error {
	base := filepath.Join(outDir, "opengrep_"+strings.ReplaceAll(platform, "/", "_"))
	if sum, err := opengrep.FileSHA256(base); err == nil && sum == a.SHA256 {
		fmt.Printf("%s: %s %s already present\n", platform, a.Name, version)
		return nil
	}

	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, version, a.Name)
	fmt.Printf("%s: downloading %s\n", platform, url)
	return (&opengrep.Download{URL: url, SHA256: a.SHA256}).Fetch(context.Background(), base)
}

// repin points every asset in the config at release tag, taking checksums
// from the digests GitHub publishes for release assets.
func repin(path string, cfg *pin.Pins, tag string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", repo, tag)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	var release struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return err
	}
	digests := map[string]string{}
	for _, a := range release.Assets {
		digests[a.Name] = strings.TrimPrefix(a.Digest, "sha256:")
	}

	for p, a := range cfg.Assets {
		d := digests[a.Name]
		if d == "" {
			return fmt.Errorf("release %s has no sha256 digest for %s (%s)", tag, a.Name, p)
		}
		a.SHA256 = d
		cfg.Assets[p] = a
	}
	cfg.Version = tag

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("pinned %s to opengrep %s\n", path, tag)
	return nil
}
