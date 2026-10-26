package main

import (
 "os"
 "path/filepath"
 "testing"
)

func TestInspectKnownHash(t *testing.T) {
 p := filepath.Join(t.TempDir(),"hello.bin")
 if err := os.WriteFile(p,[]byte("hello"),0600); err != nil { t.Fatal(err) }
 got := inspect(p,"selected-folder",0)
 if got.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" || got.Size != 5 { t.Fatalf("incorrect hash: %+v",got) }
}
func TestWalkSkipsLinksAndReportsMissingFiles(t *testing.T) {
 dir := t.TempDir(); outside := filepath.Join(t.TempDir(),"private")
 os.WriteFile(outside,[]byte("not selected"),0600)
 os.WriteFile(filepath.Join(dir,"selected"),[]byte("hello"),0600)
 if err := os.Symlink(outside,filepath.Join(dir,"link")); err != nil { t.Skip("symlinks unavailable") }
 report := scanReport{}
 if err := collectFolder(dir,&report); err != nil { t.Fatal(err) }
 if len(report.Results) != 1 || !report.CoverageLimited { t.Fatalf("link was not excluded: %+v",report) }
 if inspect(filepath.Join(dir,"missing"),"selected-folder",0).SHA256 != "" { t.Fatal("missing file cannot be hashed") }
}
func TestServerURL(t *testing.T) {
 for _, value := range []string{"https://example.com","http://127.0.0.1:3000","http://localhost:3000","http://[::1]:3000"} { if _,err := validateServer(value); err != nil { t.Errorf("valid URL rejected: %s",value) } }
 for _, value := range []string{"http://example.com","https://user:password@example.com","https://example.com/path","https://example.com?q=x","file:///tmp/test"} { if _,err := validateServer(value); err == nil { t.Errorf("invalid URL accepted: %s",value) } }
}
