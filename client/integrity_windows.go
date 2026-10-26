//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

func localInputPath(path string) bool {
	if strings.HasPrefix(path, `\\?\`) {
		path = strings.TrimPrefix(path, `\\?\`)
	}
	if strings.HasPrefix(path, `\\`) || len(path) < 3 || path[1] != ':' {
		return false
	}
	root, err := syscall.UTF16PtrFromString(path[:2] + `\`)
	if err != nil {
		return false
	}
	kind, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDriveTypeW").Call(uintptr(unsafe.Pointer(root)))
	return kind == 2 || kind == 3 || kind == 5 || kind == 6
}

type trustGUID struct {
	A uint32
	B uint16
	C uint16
	D [8]byte
}
type trustFile struct {
	Size    uint32
	Path    *uint16
	File    uintptr
	Subject uintptr
}
type trustData struct {
	Size       uint32
	Policy     uintptr
	SIP        uintptr
	UI         uint32
	Revocation uint32
	Choice     uint32
	File       *trustFile
	Action     uint32
	State      uintptr
	URL        uintptr
	Flags      uint32
	Context    uint32
	Settings   uintptr
}

func trustForFile(path string) string {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "unavailable"
	}
	file := trustFile{Path: pointer}
	file.Size = uint32(unsafe.Sizeof(file))
	// Cache-only URL retrieval: the check does not fetch certificates or revocation data.
	data := trustData{UI: 2, Choice: 1, File: &file, Action: 1, Flags: 0x1000 | 0x10}
	data.Size = uint32(unsafe.Sizeof(data))
	action := trustGUID{0x00aac56b, 0xcd44, 0x11d0, [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}
	verify := syscall.NewLazyDLL("wintrust.dll").NewProc("WinVerifyTrust")
	result, _, _ := verify.Call(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	data.Action = 2
	verify.Call(^uintptr(0), uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	switch uint32(result) {
	case 0:
		return "valid-cached"
	case 0x800b0100:
		return "unsigned"
	case 0x80096010:
		return "digest-mismatch"
	case 0x800b0101:
		return "expired"
	case 0x800b0004, 0x800b0109:
		return "untrusted"
	default:
		return "unavailable"
	}
}
