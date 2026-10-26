//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

type moduleEntry struct {
	Size         uint32
	ID           uint32
	PID          uint32
	GlobalUsage  uint32
	ProcessUsage uint32
	Base         uintptr
	BaseSize     uint32
	Module       uintptr
	Name         [256]uint16
	Path         [260]uint16
}

func gameModules() ([]processFile, bool, error) {
	processes, limited, err := runningFiles()
	if err != nil {
		return nil, true, err
	}
	kernel := syscall.NewLazyDLL("kernel32.dll")
	snapshot := kernel.NewProc("CreateToolhelp32Snapshot")
	first := kernel.NewProc("Module32FirstW")
	next := kernel.NewProc("Module32NextW")
	closeHandle := kernel.NewProc("CloseHandle")
	results := []processFile{}
	for _, process := range processes {
		name := strings.ToLower(portableBase(process.Path))
		if !strings.HasPrefix(name, "fivem") && name != "gta5.exe" && name != "gta5_enhanced.exe" {
			continue
		}
		handle, _, _ := snapshot.Call(0x8|0x10, uintptr(process.PID))
		if handle == ^uintptr(0) {
			limited = true
			continue
		}
		item := moduleEntry{}
		item.Size = uint32(unsafe.Sizeof(item))
		ok, _, _ := first.Call(handle, uintptr(unsafe.Pointer(&item)))
		if ok == 0 {
			limited = true
			closeHandle.Call(handle)
			continue
		}
		for {
			path := syscall.UTF16ToString(item.Path[:])
			if strings.HasSuffix(strings.ToLower(path), ".dll") {
				results = append(results, processFile{Path: path, PID: process.PID})
			}
			if len(results) >= 1000 {
				limited = true
				break
			}
			ok, _, lastErr := next.Call(handle, uintptr(unsafe.Pointer(&item)))
			if ok == 0 {
				if lastErr != syscall.ERROR_NO_MORE_FILES {
					limited = true
				}
				break
			}
		}
		closeHandle.Call(handle)
		if len(results) >= 1000 {
			break
		}
	}
	return results, limited, nil
}
