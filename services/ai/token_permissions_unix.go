//go:build !windows && !linux

package ai

import (
	"errors"
	"os"
)

func validateTokenFilePermissions(_ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("group or other access is forbidden")
	}
	return nil
}
