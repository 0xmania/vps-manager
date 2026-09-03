//go:build windows

package ai

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateTokenFilePermissions(file *os.File, _ os.FileInfo) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("security descriptor is unavailable")
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current == nil || current.User.Sid == nil {
		return errors.New("service identity is unavailable")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return errors.New("SYSTEM identity is unavailable")
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return errors.New("administrator identity is unavailable")
	}
	allowed := []*windows.SID{current.User.Sid, system, administrators}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !containsSID(allowed, owner) {
		return errors.New("token file owner is not trusted")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("token file has no restrictive DACL")
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return errors.New("token file DACL is invalid")
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			readMask := windows.ACCESS_MASK(windows.FILE_READ_DATA | windows.GENERIC_READ | windows.GENERIC_ALL)
			if ace.Mask&readMask == 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !containsSID(allowed, sid) {
				return errors.New("token file is readable by another identity")
			}
		default:
			return errors.New("token file contains an unsupported access rule")
		}
	}
	return nil
}

func containsSID(allowed []*windows.SID, candidate *windows.SID) bool {
	for _, sid := range allowed {
		if sid.Equals(candidate) {
			return true
		}
	}
	return false
}
