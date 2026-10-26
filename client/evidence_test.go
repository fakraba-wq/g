package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

func TestPEMetadataValidation(t *testing.T) {
	data := make([]byte, 256)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[60:], 128)
	copy(data[128:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[132:], 0x8664)
	binary.LittleEndian.PutUint32(data[136:], 1000000000)
	binary.LittleEndian.PutUint16(data[150:], 0x2000)
	info := readPE(bytes.NewReader(data))
	if info == nil || info.Machine != "x64" || !info.IsDLL || info.LinkerTimeUTC != "2001-09-09T01:46:40Z" {
		t.Fatalf("incorrect PE metadata: %+v", info)
	}
	binary.LittleEndian.PutUint32(data[60:], 0xffffffff)
	if readPE(bytes.NewReader(data)) != nil {
		t.Fatal("unsafe offset accepted")
	}
	if readPE(bytes.NewReader([]byte("MZ"))) != nil {
		t.Fatal("truncated header accepted")
	}
}
func TestUnselectedEvidenceIsNotCollected(t *testing.T) {
	report, err := scanWithOptions(context.Background(), t.TempDir(), scanOptions{Boot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Options.Activity || len(report.Evidence.Executions) != 0 {
		t.Fatal("unselected activity was collected")
	}
	if portableBase(`C:\private\sample.dll`) != "sample.dll" {
		t.Fatal("portable basename did not strip the path")
	}
}
