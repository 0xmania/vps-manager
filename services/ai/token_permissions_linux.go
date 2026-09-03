//go:build linux

package ai

import (
	"errors"
	"os"
	"syscall"
)

func validateTokenFilePermissions(_ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("group or other access is forbidden")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("token file owner does not match the service identity")
	}
	return nil
}
