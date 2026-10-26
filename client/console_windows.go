//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func enableConsole() {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	attached, _, _ := kernel.NewProc("AttachConsole").Call(^uintptr(0))
	if attached == 0 {
		kernel.NewProc("AllocConsole").Call()
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = f
		os.Stderr = f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
}
func showLaunchError(message string) {
	text, _ := syscall.UTF16PtrFromString(message)
	title, _ := syscall.UTF16PtrFromString("Crimson PC Check")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
