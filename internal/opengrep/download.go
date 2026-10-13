package opengrep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// maxDownload is the size of the largest asset that Fetch accepts.
const maxDownload = 256 << 20

// A download is retried up to downloadRetries times after a network error
// or a 5xx response, waiting firstRetry and then twice as long each time.
const (
	downloadRetries = 3
	firstRetry      = time.Second
)

// A Download is a pinned opengrep release asset to fetch: downloaded from
// URL, or copied from the local file From.
type Download struct {
	URL    string
	From   string       // if set, a local copy of the asset, used instead of URL
	Client *http.Client // nil means http.DefaultClient
	SHA256 string       // the asset's pinned SHA-256, hex

	maxBytes   int64         // 0 means maxDownload
	firstRetry time.Duration // 0 means firstRetry
}

// source returns what d fetches, as an IntegrityError names it.
func (d *Download) source() string {
	if d.From != "" {
		return d.From
	}
	return d.URL
}

// Fetch writes the asset to path, an executable. The bytes are hashed as
// they stream into a temporary file beside path, which is made executable
// and renamed into place only when their SHA-256 is d.SHA256, so no process
// ever runs a partial or altered file; a mismatch is an *IntegrityError.
// When the rename fails but a file that verifies is now in place, as when
// another process won the race (or, on Windows, runs it), that counts as
// success. A download that fails with a network error or a 5xx response is
// retried up to 3 times, after 1, 2 and 4 seconds; an asset larger than 256
// MiB is an error.
func (d *Download) Fetch(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	sum, err := d.write(ctx, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if sum != d.SHA256 {
		return &IntegrityError{Path: d.source(), Want: d.SHA256, Got: sum}
	}
	if err := os.Chmod(tmp.Name(), 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(tmp.Name())
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		if inPlace(path, d.SHA256) {
			return nil
		}
		return err
	}
	remember(path, fi, sum) // the rename kept its size and modification time
	return nil
}

// write writes the asset to f and returns its SHA-256.
func (d *Download) write(ctx context.Context, f *os.File) (string, error) {
	if d.From != "" {
		src, err := os.Open(d.From)
		if err != nil {
			return "", err
		}
		defer src.Close()
		return d.copy(f, src)
	}
	wait := d.firstRetry
	if wait == 0 {
		wait = firstRetry
	}
	for retry := 0; ; retry++ {
		sum, again, err := d.get(ctx, f)
		if err == nil || !again || retry == downloadRetries || ctx.Err() != nil {
			return sum, err
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return "", ctx.Err()
		}
		wait *= 2
		if err := f.Truncate(0); err != nil {
			return "", err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
	}
}

// get downloads the asset into f and returns its SHA-256, or the error and
// whether to try again.
func (d *Download) get(ctx context.Context, f *os.File) (sum string, again bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return "", false, err
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode >= 500, fmt.Errorf("GET %s: %s", d.URL, resp.Status)
	}
	sum, err = d.copy(f, resp.Body)
	return sum, err != nil && !errors.Is(err, errTooLarge), err
}

var errTooLarge = errors.New("larger than 256 MiB")

// copy copies r to w and returns the SHA-256 of what it copied.
func (d *Download) copy(w io.Writer, r io.Reader) (string, error) {
	limit := d.maxBytes
	if limit == 0 {
		limit = maxDownload
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(r, limit+1))
	switch {
	case err != nil:
		return "", err
	case n > limit:
		return "", fmt.Errorf("%s: %w", d.source(), errTooLarge)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Install makes the asset d available as the executable that Find finds in
// the cache directory dir, unless a verified copy is already there, and
// returns its path. A file lock in dir keeps processes from downloading it
// at once; where locking fails, Install logs why and fetches all the same.
func Install(ctx context.Context, dir string, d *Download, log *slog.Logger) (string, error) {
	path := cachePath(dir, d.SHA256)
	if got, err := FileSHA256(path); err == nil && got == d.SHA256 {
		return path, nil
	}
	unlock, err := lock(ctx, filepath.Join(dir, "locks", "install-"+d.SHA256[:16]+".lock"))
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		log.Info("installing opengrep without a lock", "err", err)
	}
	defer unlock()
	if got, err := FileSHA256(path); err == nil && got == d.SHA256 {
		return path, nil
	}
	start := time.Now()
	log.Info("installing opengrep", "from", d.source(), "path", path)
	if err := d.Fetch(ctx, path); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	log.Info("installed opengrep", "path", path, "took", time.Since(start))
	return path, nil
}
