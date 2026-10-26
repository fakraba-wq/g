package main

import (
	"encoding/binary"
	"io"
	"strings"
	"time"
)

type scanOptions struct {
	Processes bool `json:"processes"`
	Modules   bool `json:"modules"`
	Integrity bool `json:"integrity"`
	Boot      bool `json:"boot"`
	Activity  bool `json:"activity"`
}
type peInfo struct {
	Machine       string `json:"machine"`
	Timestamp     uint32 `json:"timestamp"`
	IsDLL         bool   `json:"isDLL"`
	LinkerTimeUTC string `json:"linkerTimeUTC,omitempty"`
}
type collection struct {
	Key   string `json:"key"`
	State string `json:"state"`
	Count int    `json:"count"`
	Note  string `json:"note"`
}
type bootFacts struct {
	WindowsVersion    string `json:"windowsVersion"`
	BIOSVendor        string `json:"biosVendor"`
	BIOSVersion       string `json:"biosVersion"`
	BoardManufacturer string `json:"boardManufacturer"`
	BoardProduct      string `json:"boardProduct"`
	LastBootUTC       string `json:"lastBootUTC"`
	FastBootEnabled   *bool  `json:"fastBootEnabled,omitempty"`
}
type execution struct {
	Name      string `json:"name"`
	TimeUTC   string `json:"timeUTC"`
	Source    string `json:"source"`
	EventID   int    `json:"eventId"`
	PathState string `json:"pathState"`
}
type evidence struct {
	Boot           *bootFacts   `json:"boot,omitempty"`
	Executions     []execution  `json:"executions,omitempty"`
	WindowStartUTC string       `json:"windowStartUTC,omitempty"`
	Collection     []collection `json:"collection,omitempty"`
}

func readPE(file io.ReaderAt) *peInfo {
	dos := make([]byte, 64)
	if _, err := file.ReadAt(dos, 0); err != nil || string(dos[:2]) != "MZ" {
		return nil
	}
	offset := int64(binary.LittleEndian.Uint32(dos[60:]))
	if offset < 64 || offset > 1024*1024 {
		return nil
	}
	header := make([]byte, 24)
	if _, err := file.ReadAt(header, offset); err != nil || string(header[:4]) != "PE\x00\x00" {
		return nil
	}
	machines := map[uint16]string{0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}
	machine := machines[binary.LittleEndian.Uint16(header[4:])]
	if machine == "" {
		machine = "unknown"
	}
	stamp := binary.LittleEndian.Uint32(header[8:])
	info := &peInfo{Machine: machine, Timestamp: stamp, IsDLL: binary.LittleEndian.Uint16(header[22:])&0x2000 != 0}
	if stamp != 0 {
		info.LinkerTimeUTC = time.Unix(int64(stamp), 0).UTC().Format(time.RFC3339)
	}
	return info
}
func portableBase(path string) string {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
