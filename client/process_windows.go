//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

type processEntry struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	BasePriority    int32
	Flags           uint32
	ExeFile         [260]uint16
}

func runningFiles() ([]processFile, bool, error) {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	snapshotProc := kernel.NewProc("CreateToolhelp32Snapshot")
	firstProc := kernel.NewProc("Process32FirstW")
	nextProc := kernel.NewProc("Process32NextW")
	openProc := kernel.NewProc("OpenProcess")
	pathProc := kernel.NewProc("QueryFullProcessImageNameW")
	closeProc := kernel.NewProc("CloseHandle")
	snapshot, _, err := snapshotProc.Call(2, 0)
	if snapshot == ^uintptr(0) {
		return nil, true, fmt.Errorf("process snapshot unavailable: %v", err)
	}
	defer closeProc.Call(snapshot)
	item := processEntry{}
	item.Size = uint32(unsafe.Sizeof(item))
	ok, _, err := firstProc.Call(snapshot, uintptr(unsafe.Pointer(&item)))
	if ok == 0 {
		return nil, true, fmt.Errorf("process enumeration unavailable: %v", err)
	}
	results := []processFile{}
	limited := false
	for {
		if item.ProcessID != 0 && item.ProcessID != 4 {
			handle, _, _ := openProc.Call(0x1000, 0, uintptr(item.ProcessID))
			if handle == 0 {
				limited = true
			} else {
				var path [32768]uint16
				length := uint32(len(path))
				found, _, _ := pathProc.Call(handle, 0, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&length)))
				if found != 0 {
					results = append(results, processFile{Path: syscall.UTF16ToString(path[:length]), PID: item.ProcessID})
				} else {
					limited = true
				}
				closeProc.Call(handle)
			}
		}
		next, _, nextErr := nextProc.Call(snapshot, uintptr(unsafe.Pointer(&item)))
		if next == 0 {
			if nextErr != syscall.ERROR_NO_MORE_FILES {
				limited = true
			}
			break
		}
	}
	return results, limited, nil
}
