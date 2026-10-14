package gogrep

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/odipar/gogrep/internal/opengrep"
)

// serveAssets starts a server of the release asset that pinned pins,
// serving data, and returns its URL and a count of the requests for it.
func serveAssets(t *testing.T, data []byte) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mirror/v1.30.2/opengrep_test" {
			http.NotFound(w, r)
			return
		}
		n.Add(1)
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

func TestInstallOpengrep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sum := opengrep.SHA256(fakeOpengrep)
	url, n := serveAssets(t, fakeOpengrep)
	cache := t.TempDir()
	e := newPinnedEngine(t, Config{CacheDir: cache})
	want := OpengrepInfo{Path: exe(filepath.Join(cache, "opengrep-"+sum[:16])), Source: "cache", SHA256: sum, Pinned: true, Version: "v1.30.2"}
	for range 2 {
		info, err := e.InstallOpengrep(ctx, &InstallOptions{BaseURL: url + "/mirror/", Platform: runtime.GOOS + "/" + runtime.GOARCH})
		if err != nil || *info != want {
			t.Fatalf("InstallOpengrep = %+v, %v; want %+v", info, err, want)
		}
	}
	if n.Load() != 1 {
		t.Errorf("two installs made %d requests, want 1", n.Load())
	}
	if info, err := e.Opengrep(ctx); err != nil || *info != want {
		t.Errorf("Opengrep after the install = %+v, %v; want %+v", info, err, want)
	}

	// Config.Opengrep comes first, and an embedded opengrep is only
	// extracted.
	other := exe(t.TempDir())
	if err := os.WriteFile(other, []byte("another opengrep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if info, err := newPinnedEngine(t, Config{Opengrep: other}).InstallOpengrep(ctx, &InstallOptions{BaseURL: url + "/mirror"}); err != nil || info.Source != "config" || n.Load() != 2 {
		t.Errorf("InstallOpengrep with Config.Opengrep = %+v, %v, after %d requests; want an install, and Config.Opengrep", info, err, n.Load())
	}
	if info, err := newPinnedEngine(t, Config{EmbeddedOpengrep: fakeOpengrep}).InstallOpengrep(ctx, &InstallOptions{BaseURL: url + "/mirror"}); err != nil || info.Source != "embedded" || n.Load() != 2 {
		t.Errorf("InstallOpengrep with an embedded opengrep = %+v, %v, after %d requests; want no download", info, err, n.Load())
	}

	from := filepath.Join(t.TempDir(), "opengrep_test")
	if err := os.WriteFile(from, fakeOpengrep, 0o600); err != nil {
		t.Fatal(err)
	}
	cache = t.TempDir()
	if info, err := newPinnedEngine(t, Config{CacheDir: cache}).InstallOpengrep(ctx, &InstallOptions{From: from}); err != nil || info.Source != "cache" || n.Load() != 2 {
		t.Errorf("InstallOpengrep from a file = %+v, %v, after %d requests; want no download", info, err, n.Load())
	}
}

func TestInstallOpengrepErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sum := opengrep.SHA256(fakeOpengrep)
	url, _ := serveAssets(t, []byte("altered"))
	cache := t.TempDir()
	e := newPinnedEngine(t, Config{CacheDir: cache})

	_, err := e.InstallOpengrep(ctx, &InstallOptions{BaseURL: url + "/mirror"})
	var ie *IntegrityError
	if !errors.As(err, &ie) || *ie != (IntegrityError{Path: url + "/mirror/v1.30.2/opengrep_test", Want: sum, Got: opengrep.SHA256([]byte("altered"))}) || errors.Is(err, ErrNoOpengrep) {
		t.Errorf("InstallOpengrep of an altered asset = %#v, want an *IntegrityError", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(cache, "opengrep-"+sum[:16])); len(entries) != 0 {
		t.Errorf("an altered asset left %v", entries)
	}
	if _, err := e.InstallOpengrep(ctx, &InstallOptions{BaseURL: url}); err == nil || !strings.HasPrefix(err.Error(), "installing opengrep v1.30.2 for "+runtime.GOOS+"/"+runtime.GOARCH+": GET "+url+"/v1.30.2/opengrep_test: 404 Not Found") {
		t.Errorf("InstallOpengrep of a missing asset = %v", err)
	}

	for _, tt := range []struct {
		opts *InstallOptions
		err  string
	}{
		{&InstallOptions{Platform: "plan9/amd64"}, "InstallOptions.Platform plan9/amd64 is not this platform, " + runtime.GOOS + "/" + runtime.GOARCH},
		{&InstallOptions{Platform: runtime.GOOS + "/" + runtime.GOARCH + "/musl"}, "no usable opengrep: opengrep.json pins no opengrep for " + runtime.GOOS + "/" + runtime.GOARCH + "/musl"},
		{&InstallOptions{From: "opengrep_test"}, "InstallOptions.From opengrep_test is not an absolute path"},
		{&InstallOptions{BaseURL: "ftp://example.com"}, "InstallOptions.BaseURL ftp://example.com is not an http or https URL"},
	} {
		if _, err := e.InstallOpengrep(ctx, tt.opts); err == nil || err.Error() != tt.err {
			t.Errorf("InstallOpengrep(%+v) = %v, want %q", tt.opts, err, tt.err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.InstallOpengrep(ctx, &InstallOptions{BaseURL: url}); !errors.Is(err, context.Canceled) {
		t.Errorf("InstallOpengrep with a done ctx = %v, want context.Canceled", err)
	}
}
