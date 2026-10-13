package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"

	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/pin"
)

// OpengrepInfo describes the opengrep executable an Engine runs.
type OpengrepInfo struct {
	Path    string // absolute path of the executable
	Source  string // "config", "embedded", "cache" or "path"
	SHA256  string // hex SHA-256 of the executable
	Pinned  bool   // SHA256 is the pinned asset's for this platform
	Version string // the pinned version, such as "v1.30.2", when Pinned; "" otherwise
}

// Opengrep finds the opengrep executable and prepares it to run, without
// using the network. It tries, in order: Config.Opengrep;
// Config.EmbeddedOpengrep, written to CacheDir; the pinned executable in
// CacheDir; opengrep on PATH, if its SHA-256 is the pinned one or
// Config.AllowUnpinned is set. A checksum is computed once per process for
// each path, size and modification time. The first time an executable is
// used with a CacheDir, Opengrep unpacks opengrep's runtime (about 245 MB
// and 8 s) privately and publishes it there, so that concurrent opengrep
// processes never start from a half-written runtime.
//
// Scan, Test and Command call Opengrep; call it yourself to fail early.
// When no opengrep is found, it returns an error that wraps ErrNoOpengrep
// and names the pinned version, platform, asset, checksum, cache path and
// remedies.
func (e *Engine) Opengrep(ctx context.Context) (*OpengrepInfo, error) {
	info, _, err := e.opengrep(ctx)
	return info, err
}

// opengrep returns the executable that Opengrep returns, and the
// XDG_CACHE_HOME of its prepared runtime: "" for none, which leaves opengrep
// where it keeps its runtime by itself. It marks both as used (see
// PruneCache).
func (e *Engine) opengrep(ctx context.Context) (*OpengrepInfo, string, error) {
	info, err := e.find(ctx)
	if err != nil || e.cacheErr != nil {
		return info, "", err
	}
	xdg, err := opengrep.PrepareRuntime(ctx, info.Path, info.SHA256, e.cacheDir, opengrep.UTF8Env(opengrep.HermeticEnv(e.env)), e.log)
	if err != nil {
		return nil, "", err
	}
	e.markUsed(info)
	return info, xdg, nil
}

// find finds the executable that Opengrep returns.
func (e *Engine) find(ctx context.Context) (*OpengrepInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pins, err := e.pins()
	if err != nil {
		return nil, &noOpengrep{err}
	}
	keys := pin.Keys(runtime.GOOS, runtime.GOARCH, musl())
	f := &opengrep.Finder{Explicit: e.cfg.Opengrep, CacheDir: e.cacheDir, AllowUnpinned: e.cfg.AllowUnpinned}
	for _, key := range keys {
		if a, ok := pins.Assets[key]; ok {
			f.Pinned = append(f.Pinned, a.SHA256)
		}
	}
	if f.Explicit == "" && len(e.cfg.EmbeddedOpengrep) > 0 {
		if len(f.Pinned) == 0 {
			return nil, &noOpengrep{fmt.Errorf("opengrep.json pins no opengrep for %s/%s", runtime.GOOS, runtime.GOARCH)}
		}
		if e.cacheErr != nil {
			return nil, &noOpengrep{fmt.Errorf("extracting the embedded opengrep: %w", e.cacheErr)}
		}
		f.Embedded, f.EmbeddedSum = e.cfg.EmbeddedOpengrep, e.embeddedSum()
	}

	exe, err := f.Find()
	var ie *opengrep.IntegrityError
	switch {
	case errors.As(err, &ie):
		return nil, (*IntegrityError)(ie)
	case errors.Is(err, opengrep.ErrNotFound):
		return nil, e.notFound(pins, keys)
	case err != nil:
		return nil, &noOpengrep{err}
	}
	info := &OpengrepInfo{Path: exe.Path, Source: exe.Source, SHA256: exe.SHA256, Pinned: exe.Pinned}
	if exe.Pinned {
		info.Version = pins.Version
	}
	e.log.Debug("found opengrep", "path", info.Path, "source", info.Source, "sha256", info.SHA256, "pinned", info.Pinned)
	return info, nil
}

// notFound returns the error for finding no opengrep, given the platform
// keys under which pins may hold this platform's opengrep.
func (e *Engine) notFound(pins *pin.Pins, keys []string) error {
	onPath := "no opengrep on PATH has that SHA-256"
	if e.cfg.AllowUnpinned {
		onPath = "there is no opengrep on PATH"
	}
	for _, key := range keys {
		a, ok := pins.Assets[key]
		if !ok {
			continue
		}
		where := filepath.Join(e.cacheDir, "opengrep-"+a.SHA256[:16])
		if e.cacheErr != nil {
			where = fmt.Sprintf("the cache (%v)", e.cacheErr)
		}
		return fmt.Errorf("%w: %s for %s (asset %s, sha256 %s…) is not in %s, and %s; install it with Engine.InstallOpengrep or `gogrep install-opengrep`, or set Config.Opengrep",
			ErrNoOpengrep, pins.Version, key, a.Name, a.SHA256[:16], where, onPath)
	}
	if e.cfg.AllowUnpinned {
		return fmt.Errorf("%w: opengrep.json pins no opengrep for %s/%s, and %s; set Config.Opengrep", ErrNoOpengrep, runtime.GOOS, runtime.GOARCH, onPath)
	}
	return fmt.Errorf("%w: opengrep.json pins no opengrep for %s/%s; set Config.Opengrep, or Config.AllowUnpinned to run the one on PATH", ErrNoOpengrep, runtime.GOOS, runtime.GOARCH)
}

// musl reports whether this is a Linux system whose programs use musl libc.
var musl = sync.OnceValue(func() bool {
	root, ok := os.DirFS("/").(fs.StatFS)
	return runtime.GOOS == "linux" && ok && pin.Musl(root, runtime.GOARCH)
})

// withRuntime returns env with XDG_CACHE_HOME set to xdg, unless xdg is "".
func withRuntime(env []string, xdg string) []string {
	if xdg == "" {
		return env
	}
	return append(slices.Clip(env), "XDG_CACHE_HOME="+xdg)
}
