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

// Open a separate browser app window, with no terminal and no browser tabs.
// Never invoke a shell or an executable from the current working directory.
func openBrowser(url string) error {
	candidates := []string{}
	for _, key := range []string{"ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"} {
		if base := os.Getenv(key); base != "" {
			candidates = append(candidates, filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"), filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"))
		}
	}
	for _, path := range candidates {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			continue
		}
		command := exec.Command(path, "--app="+url, "--window-size=1000,850")
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if command.Start() == nil {
			go command.Wait()
			return nil
		}
	}
	command := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "rundll32.exe"), "url.dll,FileProtocolHandler", url)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
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
