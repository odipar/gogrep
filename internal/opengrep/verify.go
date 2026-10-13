package opengrep

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

// An IntegrityError reports an opengrep executable whose SHA-256 is not the
// pinned one.
type IntegrityError struct {
	Path string // the file or URL concerned; "embedded" for an embedded executable
	Want string // the pinned SHA-256, hex
	Got  string // the SHA-256 of the bytes, hex
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("%s: SHA-256 %s, want the pinned %s", e.Path, e.Got, e.Want)
}

// SHA256 returns the hex SHA-256 of data.
func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// A fileKey identifies the contents of a file for fileSums.
type fileKey struct {
	path  string
	size  int64
	mtime int64 // modification time, in Unix nanoseconds
}

// fileSums are the checksums FileSHA256 computed in this process.
var fileSums struct {
	sync.Mutex
	m map[fileKey]string
}

// FileSHA256 returns the hex SHA-256 of the file at path. It reads each path,
// size and modification time once per process.
func FileSHA256(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	fileSums.Lock()
	sum, ok := fileSums.m[keyOf(path, fi)]
	fileSums.Unlock()
	if ok {
		return sum, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil { // the file read, should path have changed
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum = hex.EncodeToString(h.Sum(nil))
	remember(path, fi, sum)
	return sum, nil
}

func keyOf(path string, fi os.FileInfo) fileKey {
	return fileKey{path, fi.Size(), fi.ModTime().UnixNano()}
}

// remember records that the file at path, as fi describes it, has the
// checksum sum.
func remember(path string, fi os.FileInfo, sum string) {
	fileSums.Lock()
	defer fileSums.Unlock()
	if fileSums.m == nil {
		fileSums.m = map[fileKey]string{}
	}
	fileSums.m[keyOf(path, fi)] = sum
}
