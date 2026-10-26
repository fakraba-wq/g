//go:build !windows

package main

func trustForFile(path string) string { return "unavailable" }
func localInputPath(path string) bool { return true }
