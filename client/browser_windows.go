//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

func openBrowser(url string) error {
	command := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "rundll32.exe"), "url.dll,FileProtocolHandler", url)
	if err := command.Start(); err != nil {
		return err
	}
	go command.Wait()
	return nil
}

type browseInfo struct {
	Owner    uintptr
	Root     uintptr
	Display  *uint16
	Title    *uint16
	Flags    uint32
	Callback uintptr
	Param    uintptr
	Image    int32
}

func pickFolder() (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ole := syscall.NewLazyDLL("ole32.dll")
	shell := syscall.NewLazyDLL("shell32.dll")
	result, _, _ := ole.NewProc("CoInitializeEx").Call(0, 2)
	if result != 0 && result != 1 {
		return "", errors.New("sélecteur de dossier indisponible")
	}
	defer ole.NewProc("CoUninitialize").Call()
	title, _ := syscall.UTF16PtrFromString("Crimson PC Check — choisir le dossier à vérifier")
	var display [260]uint16
	info := browseInfo{Display: &display[0], Title: title, Flags: 0x41}
	pidl, _, _ := shell.NewProc("SHBrowseForFolderW").Call(uintptr(unsafe.Pointer(&info)))
	if pidl == 0 {
		return "", nil
	}
	defer ole.NewProc("CoTaskMemFree").Call(pidl)
	var path [32768]uint16
	ok, _, _ := shell.NewProc("SHGetPathFromIDListEx").Call(pidl, uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)), 0)
	if ok == 0 {
		return "", errors.New("impossible de lire ce chemin")
	}
	return syscall.UTF16ToString(path[:]), nil
}
