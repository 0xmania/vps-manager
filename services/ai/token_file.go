package ai

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const maxTokenBytes = 4096

func readTokenFile(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("token path is not absolute")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("token file is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("token file is unavailable")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() < 1 || after.Size() > maxTokenBytes {
		return nil, errors.New("token file is unsafe")
	}
	if err := validateTokenFilePermissions(file, after); err != nil {
		return nil, errors.New("token file permissions are unsafe")
	}
	buffer, err := io.ReadAll(io.LimitReader(file, maxTokenBytes+1))
	if err != nil || len(buffer) > maxTokenBytes {
		wipe(buffer)
		return nil, errors.New("token file could not be read safely")
	}
	token := bytes.TrimSpace(buffer)
	if len(token) == 0 || len(token) > maxTokenBytes || !validToken(token) {
		wipe(buffer)
		return nil, errors.New("token file content is invalid")
	}
	result := make([]byte, len(token))
	copy(result, token)
	wipe(buffer)
	return result, nil
}

func validToken(token []byte) bool {
	if len(token) == 0 {
		return false
	}
	for _, value := range token {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}
