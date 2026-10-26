//go:build windows

package main

import (
	"os"
	"syscall"
)

func unsafeLink(path string, info os.FileInfo) bool {
	if info != nil && info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	a, err := syscall.GetFileAttributes(p)
	return err != nil || a&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
