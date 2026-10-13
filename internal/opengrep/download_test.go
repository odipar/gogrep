package opengrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// asset is the content of the release asset the download tests serve.
var asset = bytes.Repeat([]byte("opengrep\n"), 100000)

// serve starts a server that answers the nth request for /asset with the
// nth of statuses, and with asset once they run out; /redirect redirects
// there. It returns the server's URL and a count of the requests for /asset.
func serve(t *testing.T, statuses ...int) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/asset", func(w http.ResponseWriter, r *http.Request) {
		if i := int(n.Add(1)) - 1; i < len(statuses) {
			w.WriteHeader(statuses[i])
			return
		}
		w.Write(asset)
	})
	mux.Handle("/redirect", http.RedirectHandler("/asset", http.StatusFound))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

// checkInstalled checks that path holds asset, executable by its owner
// only, and that its directory holds nothing else.
func checkInstalled(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, asset) {
		t.Errorf("%s holds %d bytes, %v; want the asset's %d", path, len(data), err, len(asset))
	}
	if fi, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Errorf("%s has mode %v, want 0700", path, fi.Mode().Perm())
	}
	checkOnly(t, filepath.Dir(path), filepath.Base(path))
}

// checkOnly checks that dir holds the files names and no others.
func checkOnly(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if !slices.Equal(got, names) {
		t.Errorf("%s holds %q, want %q", dir, got, names)
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sum := SHA256(asset)
	tests := []struct {
		name     string
		path     string // /asset or /redirect
		statuses []int  // the first answers
		requests int32
		err      string // the error's text, with URL for the server's
	}{
		{"ok", "/asset", nil, 1, ""},
		{"redirect", "/redirect", nil, 1, ""},
		{"retried", "/asset", []int{503, 502}, 3, ""},
		{"too many 5xx", "/asset", []int{503, 503, 503, 503}, 4, "GET URL/asset: 503 Service Unavailable"},
		{"not found", "/asset", []int{404}, 1, "GET URL/asset: 404 Not Found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url, n := serve(t, tt.statuses...)
			path := filepath.Join(t.TempDir(), "opengrep")
			err := (&Download{URL: url + tt.path, SHA256: sum, firstRetry: time.Millisecond}).Fetch(ctx, path)
			if n.Load() != tt.requests {
				t.Errorf("Fetch made %d requests, want %d", n.Load(), tt.requests)
			}
			if tt.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				checkInstalled(t, path)
				return
			}
			if want := strings.ReplaceAll(tt.err, "URL", url); err == nil || err.Error() != want {
				t.Errorf("Fetch = %v, want %q", err, want)
			}
			checkOnly(t, filepath.Dir(path))
		})
	}

	t.Run("altered", func(t *testing.T) {
		t.Parallel()
		url, _ := serve(t)
		path := filepath.Join(t.TempDir(), "opengrep")
		want := SHA256([]byte("the pinned opengrep"))
		err := (&Download{URL: url + "/asset", SHA256: want}).Fetch(ctx, path)
		var ie *IntegrityError
		if !errors.As(err, &ie) || *ie != (IntegrityError{Path: url + "/asset", Want: want, Got: sum}) {
			t.Errorf("Fetch of an altered asset = %#v, want an *IntegrityError", err)
		}
		checkOnly(t, filepath.Dir(path))
	})

	t.Run("too large", func(t *testing.T) {
		t.Parallel()
		url, n := serve(t)
		path := filepath.Join(t.TempDir(), "opengrep")
		err := (&Download{URL: url + "/asset", SHA256: sum, maxBytes: int64(len(asset)) - 1, firstRetry: time.Millisecond}).Fetch(ctx, path)
		if err == nil || err.Error() != url+"/asset: larger than 256 MiB" || n.Load() != 1 {
			t.Errorf("Fetch of a large asset = %v, after %d requests; want one, and an error", err, n.Load())
		}
		checkOnly(t, filepath.Dir(path))
	})

	t.Run("from", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		from, path := filepath.Join(dir, "asset"), filepath.Join(dir, "cache", "opengrep")
		if err := os.WriteFile(from, asset, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := (&Download{From: from, URL: "http://invalid.invalid/", SHA256: sum}).Fetch(ctx, path); err != nil {
			t.Fatal(err)
		}
		checkInstalled(t, path)
		want := SHA256([]byte("another"))
		err := (&Download{From: from, SHA256: want}).Fetch(ctx, filepath.Join(dir, "other", "opengrep"))
		var ie *IntegrityError
		if !errors.As(err, &ie) || *ie != (IntegrityError{Path: from, Want: want, Got: sum}) {
			t.Errorf("Fetch of an altered From = %#v, want an *IntegrityError", err)
		}
		checkOnly(t, filepath.Join(dir, "other"))
	})
}

// A download that breaks off is retried, and one that ctx ends is not.
func TestFetchInterrupted(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(asset)))
		if n.Add(1) == 1 {
			w.Write(asset[:1000]) // and the connection closes
			return
		}
		if r.URL.Path == "/hang" {
			w.Write(asset[:1000])
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		w.Write(asset)
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	ctx := context.Background()
	sum := SHA256(asset)

	path := filepath.Join(t.TempDir(), "opengrep")
	if err := (&Download{URL: srv.URL + "/asset", SHA256: sum, firstRetry: time.Millisecond}).Fetch(ctx, path); err != nil || n.Load() != 2 {
		t.Fatalf("Fetch of a download that broke off = %v, after %d requests; want it retried once", err, n.Load())
	}
	checkInstalled(t, path)

	ctx, cancel := context.WithCancel(ctx)
	path = filepath.Join(t.TempDir(), "opengrep")
	done := make(chan error, 1)
	go func() { done <- (&Download{URL: srv.URL + "/hang", SHA256: sum}).Fetch(ctx, path) }()
	for n.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Fetch, cancelled = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Fetch still runs after its ctx was cancelled")
	}
	checkOnly(t, filepath.Dir(path))
}

func TestInstall(t *testing.T) {
	t.Parallel()
	url, n := serve(t)
	dir := t.TempDir()
	d := &Download{URL: url + "/asset", SHA256: SHA256(asset)}
	log := slog.New(slog.DiscardHandler)
	for range 2 {
		path, err := Install(context.Background(), dir, d, log)
		if err != nil || path != cachePath(dir, d.SHA256) {
			t.Fatalf("Install = %s, %v; want %s", path, err, cachePath(dir, d.SHA256))
		}
		checkInstalled(t, path)
	}
	if n.Load() != 1 {
		t.Errorf("two Installs made %d requests, want 1: the second finds the first's copy", n.Load())
	}
	checkOnly(t, dir, "locks", "opengrep-"+d.SHA256[:16])

	// A cached copy that fails verification is replaced.
	path := cachePath(dir, d.SHA256)
	if err := os.WriteFile(path, []byte("damaged"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), dir, d, log); err != nil || n.Load() != 2 {
		t.Errorf("Install over a damaged copy = %v, after %d requests; want a download", err, n.Load())
	}
	checkInstalled(t, path)
}

// An Install whose ctx is done releases the lock it took: on Windows, the
// open lock file could not even be removed.
func TestInstallCancelled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	d := &Download{URL: "http://127.0.0.1:1/asset", SHA256: SHA256(asset)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Install(ctx, dir, d, slog.New(slog.DiscardHandler)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Install with a done ctx = %v, want context.Canceled", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*lockPoll)
	defer cancel()
	unlock, err := lock(ctx, filepath.Join(dir, "locks", "install-"+d.SHA256[:16]+".lock"))
	if err != nil {
		t.Fatalf("taking the lock after a cancelled Install: %v; want it released", err)
	}
	unlock()
}

// Processes that install into one cold cache at once leave one executable
// and no temporary files, and download it once.
func TestInstallConcurrently(t *testing.T) {
	t.Parallel()
	url, n := serve(t)
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sum := SHA256(asset)
	outs := make([][]byte, 6)
	var wg sync.WaitGroup
	for i := range outs {
		wg.Go(func() {
			cmd := exec.Command(exe, url+"/asset", sum, dir)
			cmd.Env = append(os.Environ(), "GOGREP_TEST_HELPER=install")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("an install: %v: %s", err, out)
			}
			outs[i] = out
		})
	}
	wg.Wait()
	want := cachePath(dir, sum) + "\n"
	for _, out := range outs {
		if string(out) != want {
			t.Errorf("an install printed %q, want %q", out, want)
		}
	}
	checkInstalled(t, cachePath(dir, sum))
	if n.Load() != 1 {
		t.Errorf("6 installs made %d requests, want 1", n.Load())
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), ".") {
			t.Errorf("a temporary file is left: %s", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
