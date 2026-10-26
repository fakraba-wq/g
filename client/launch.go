package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

type launchConfig struct {
	Server string `json:"server"`
	Code   string `json:"code"`
}

func validCode(code string) bool {
	if len(code) == 6 {
		return strings.Trim(code, "0123456789") == ""
	}
	if len(code) != 8 {
		return false
	}
	for _, character := range code {
		if !strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", character) {
			return false
		}
	}
	return true
}
func readLaunchConfig(path string) launchConfig {
	f, err := os.Open(path)
	if err != nil {
		return launchConfig{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() < 12 {
		return launchConfig{}
	}
	footer := make([]byte, 12)
	if _, err = f.ReadAt(footer, info.Size()-12); err != nil || string(footer[4:]) != "CRMSNCFG" {
		return launchConfig{}
	}
	length := int64(binary.LittleEndian.Uint32(footer[:4]))
	if length < 1 || length > 4096 || length+12 > info.Size() {
		return launchConfig{}
	}
	data := make([]byte, length)
	if _, err = f.ReadAt(data, info.Size()-12-length); err != nil {
		return launchConfig{}
	}
	var config launchConfig
	if json.Unmarshal(data, &config) != nil {
		return launchConfig{}
	}
	server, err := validateServer(config.Server)
	if err != nil || !validCode(config.Code) {
		return launchConfig{}
	}
	config.Server = server
	return config
}
func main() {
	server := flag.String("server", "", "Staff server URL")
	code := flag.String("code", "", "Six-digit session code")
	cli := flag.Bool("cli", false, "Use the legacy terminal interface")
	noOpen := flag.Bool("no-open", false, "Print the guided interface URL without opening a browser")
	flag.Parse()
	if path, err := os.Executable(); err == nil {
		config := readLaunchConfig(path)
		if *server == "" {
			*server = config.Server
		}
		if *code == "" {
			*code = config.Code
		}
	}
	var err error
	if *cli {
		err = runCLI(*server, *code)
	} else {
		if *server == "" {
			*server = "http://localhost:3000"
		}
		err = runGuided(*server, *code, *noOpen)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Crimson PC Check:", err)
		fmt.Println("Press Enter to close.")
		bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(1)
	}
	if *cli {
		fmt.Println("Press Enter to close.")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
