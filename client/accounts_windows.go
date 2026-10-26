//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func steamRoots() []string {
	roots := []string{}
	for _, key := range []string{"ProgramFiles(x86)", "ProgramFiles"} {
		if base := os.Getenv(key); base != "" {
			roots = append(roots, filepath.Join(base, "Steam"))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "reg.exe"), "query", `HKCU\Software\Valve\Steam`, "/v", "SteamPath")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := cmd.Output(); err == nil && len(output) < 8192 {
		for _, line := range strings.Split(string(output), "\n") {
			if strings.Contains(line, "SteamPath") {
				parts := strings.SplitN(line, "REG_SZ", 2)
				if len(parts) == 2 {
					roots = append(roots, strings.TrimSpace(parts[1]))
				}
			}
		}
	}
	return roots
}
