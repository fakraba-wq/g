//go:build !windows

package main

import "os"

func unsafeLink(path string, info os.FileInfo) bool {
	if info == nil {
		var err error
		info, err = os.Lstat(path)
		if err != nil {
			return true
		}
	}
	return info.Mode()&os.ModeSymlink != 0
}
