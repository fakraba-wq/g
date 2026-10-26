//go:build !windows

package main

import "errors"

func runningFiles() ([]processFile, bool, error) {
	return nil, true, errors.New("running-process inspection requires Windows")
}
