//go:build !windows

package main

import "errors"

func gameModules() ([]processFile, bool, error) {
	return nil, true, errors.New("FiveM module listing requires Windows")
}
