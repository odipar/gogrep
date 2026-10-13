package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/pin"
)

// defaultBaseURL is where opengrep's release assets are downloaded from.
const defaultBaseURL = "https://github.com/opengrep/opengrep/releases/download"

// InstallOptions configure Engine.InstallOpengrep; nil means the zero
// InstallOptions, which download the pinned asset for this platform from
// GitHub.
type InstallOptions struct {
	// From is a local copy of the pinned release asset to install instead
	// of downloading it, for machines without network access: an absolute
	// path. It is verified exactly like a download.
	From string

	// BaseURL is where assets are downloaded from, as
	// <BaseURL>/<version>/<asset>. Empty means
	// https://github.com/opengrep/opengrep/releases/download. A mirror must
	// serve identical bytes, since they are checked against the pin.
	BaseURL string

	// Client makes the download. nil means http.DefaultClient, whose
	// transport honours HTTPS_PROXY and NO_PROXY.
	Client *http.Client

	// Platform picks the build for the running GOOS/GOARCH: "GOOS/GOARCH",
	// or "linux/amd64/musl" and "linux/arm64/musl" for musl libc. Empty
	// means the build the engine detects. Another GOOS/GOARCH is an error.
	Platform string
}

// InstallOpengrep makes the pinned opengrep available in CacheDir, prepares
// its runtime, and returns what Opengrep then returns. With
// Config.EmbeddedOpengrep set, it only extracts that. Otherwise, unless
// CacheDir already holds a verified copy, it copies From or downloads the
// asset (at most 256 MiB, retried up to 3 times on network errors and 5xx
// responses). The bytes are hashed as they stream into a temporary file and
// compared with the SHA-256 in this module's opengrep.json before the file
// is made executable and renamed into place, so a partial or altered file is
// never run; a mismatch is an *IntegrityError. Concurrent installs, in one
// process or several, never expose a partial file.
//
// InstallOpengrep is the only method that uses the network, and only when it
// must download. Config.Opengrep, if set, still takes precedence over the
// installed copy.
func (e *Engine) InstallOpengrep(ctx context.Context, opts *InstallOptions) (*OpengrepInfo, error) {
	if opts == nil {
		opts = &InstallOptions{}
	}
	if len(e.cfg.EmbeddedOpengrep) > 0 {
		return e.Opengrep(ctx)
	}
	pins, err := e.pins()
	if err != nil {
		return nil, err
	}
	key, err := installKey(pins, opts.Platform)
	if err != nil {
		return nil, err
	}
	if opts.From != "" && !filepath.IsAbs(opts.From) {
		return nil, fmt.Errorf("InstallOptions.From %s is not an absolute path", opts.From)
	}
	base := cmp.Or(opts.BaseURL, defaultBaseURL)
	if u, err := url.Parse(base); err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("InstallOptions.BaseURL %s is not an http or https URL", opts.BaseURL)
	}
	if e.cacheErr != nil {
		return nil, fmt.Errorf("installing opengrep: %w", e.cacheErr)
	}
	a := pins.Assets[key]
	d := &opengrep.Download{
		URL:    strings.TrimSuffix(base, "/") + "/" + pins.Version + "/" + a.Name,
		From:   opts.From,
		Client: opts.Client,
		SHA256: a.SHA256,
	}
	if _, err := opengrep.Install(ctx, e.cacheDir, d, e.log); err != nil {
		var ie *opengrep.IntegrityError
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.As(err, &ie):
			return nil, (*IntegrityError)(ie)
		}
		return nil, fmt.Errorf("installing opengrep %s for %s: %w", pins.Version, key, err)
	}
	return e.Opengrep(ctx)
}

// installKey returns the key of the asset in pins that InstallOpengrep
// installs for the platform p, as InstallOptions.Platform describes it.
func installKey(pins *pin.Pins, p string) (string, error) {
	keys := pin.Keys(runtime.GOOS, runtime.GOARCH, musl())
	if p != "" {
		if !slices.Contains([]string{runtime.GOOS + "/" + runtime.GOARCH, runtime.GOOS + "/" + runtime.GOARCH + "/musl"}, p) {
			return "", fmt.Errorf("InstallOptions.Platform %s is not this platform, %s/%s", p, runtime.GOOS, runtime.GOARCH)
		}
		keys = []string{p}
	}
	for _, key := range keys {
		if _, ok := pins.Assets[key]; ok {
			return key, nil
		}
	}
	return "", fmt.Errorf("%w: opengrep.json pins no opengrep for %s", ErrNoOpengrep, keys[0])
}
