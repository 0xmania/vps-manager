package cloudflareprovider

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

const maxTokenBytes = 16 << 10

var (
	tokenPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{20,512}$`)
	globalKeyPattern = regexp.MustCompile(`^[A-Fa-f0-9]{32,37}$`)
)

type TokenSource interface {
	Token(context.Context) ([]byte, error)
}

// FileTokenSource reads a raw Cloudflare API token from an absolute path. On
// Unix-like systems the file must not be accessible by group or other users.
type FileTokenSource struct {
	Path string
}

func (FileTokenSource) String() string { return "FileTokenSource{Path:[redacted]}" }
func (FileTokenSource) GoString() string {
	return "cloudflareprovider.FileTokenSource{Path:[redacted]}"
}

func (s FileTokenSource) Token(_ context.Context) ([]byte, error) {
	if !filepath.IsAbs(s.Path) {
		return nil, errors.New("Cloudflare API token file path must be absolute")
	}
	file, err := os.Open(s.Path)
	if err != nil {
		return nil, errors.New("open Cloudflare API token file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("Cloudflare API token file permissions are unsafe")
	}
	token, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	if err != nil || len(token) > maxTokenBytes {
		wipe(token)
		return nil, errors.New("read Cloudflare API token file")
	}
	token = bytes.TrimSpace(token)
	if err := validateToken(token); err != nil {
		wipe(token)
		return nil, err
	}
	return token, nil
}

func validateToken(token []byte) error {
	if !tokenPattern.Match(token) || globalKeyPattern.Match(token) {
		return errors.New("Cloudflare bearer API token is invalid or appears to be a Global API Key")
	}
	return nil
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
