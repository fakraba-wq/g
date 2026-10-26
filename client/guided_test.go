package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuidedConsentAndSubmission(t *testing.T) {
	var redeemed, uploaded atomic.Int32
	staff := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/sessions/redeem" {
			redeemed.Add(1)
			json.NewEncoder(w).Encode(session{SessionID: "11111111-1111-4111-8111-111111111111", UploadToken: strings.Repeat("a", 64)})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/report") {
			if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
				t.Error("missing scoped upload token")
			}
			var report scanReport
			if json.NewDecoder(r.Body).Decode(&report) != nil || len(report.Results) != 1 || report.Results[0].SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
				t.Error("incorrect evidence report")
			}
			uploaded.Add(1)
			w.WriteHeader(201)
			io.WriteString(w, `{"accepted":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer staff.Close()
	app := newGuidedApp(launchConfig{Server: staff.URL, Code: "123456"})
	local := httptest.NewServer(app)
	defer local.Close()
	app.origin = local.URL
	request := func(method, path string, body any, token bool, origin string) (int, []byte) {
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, local.URL+path, bytes.NewReader(data))
		if token {
			req.Header.Set("X-Crimson-Token", app.token)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		output, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, output
	}
	if status, _ := request("GET", "/api/config", nil, false, ""); status != 403 {
		t.Fatal("missing token was accepted")
	}
	if status, _ := request("POST", "/api/scan", map[string]any{}, true, "https://untrusted.example"); status != 403 {
		t.Fatal("foreign origin was accepted")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0600)
	body := map[string]any{"server": staff.URL, "code": "123456", "folder": dir, "consent": false}
	if status, _ := request("POST", "/api/scan", body, true, local.URL); status != 400 || redeemed.Load() != 0 {
		t.Fatal("scan started without consent")
	}
	body["consent"] = true
	body["folder"] = filepath.Join(dir, "missing")
	if status, _ := request("POST", "/api/scan", body, true, local.URL); status != 400 || redeemed.Load() != 0 {
		t.Fatal("invalid folder consumed a code")
	}
	body["folder"] = dir
	if status, data := request("POST", "/api/scan", body, true, local.URL); status != 202 {
		t.Fatalf("scan rejected: %s", data)
	}
	deadline := time.Now().Add(5 * time.Second)
	for app.snapshot().Phase != "ready" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	state := app.snapshot()
	if state.Phase != "ready" {
		t.Fatalf("scan did not finish: %+v", state)
	}
	defer os.Remove(state.ReportPath)
	if uploaded.Load() != 0 {
		t.Fatal("report uploaded automatically")
	}
	if status, _ := request("POST", "/api/share", map[string]any{"consent": false}, true, local.URL); status != 400 || uploaded.Load() != 0 {
		t.Fatal("shared without consent")
	}
	if status, data := request("POST", "/api/share", map[string]any{"consent": true}, true, local.URL); status != 200 {
		t.Fatalf("upload failed: %s", data)
	}
	if uploaded.Load() != 1 || redeemed.Load() != 1 {
		t.Fatal("unexpected upload or redemption count")
	}
	status, data := request("GET", "/api/status", nil, true, local.URL)
	if status != 200 || strings.Contains(string(data), "uploadToken") || strings.Contains(string(data), strings.Repeat("a", 64)) {
		t.Fatal("status leaked upload credentials")
	}
	if status, _ := request("POST", "/api/share", map[string]any{"consent": true}, true, local.URL); status != 409 {
		t.Fatal("duplicate share was accepted")
	}
}

func TestLaunchConfigFooter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.exe")
	config, _ := json.Marshal(launchConfig{Server: "http://localhost:3000", Code: "123456"})
	footer := make([]byte, 12)
	binary.LittleEndian.PutUint32(footer[:4], uint32(len(config)))
	copy(footer[4:], "CRMSNCFG")
	data := append(append([]byte("MZ harmless fixture"), config...), footer...)
	os.WriteFile(path, data, 0600)
	if got := readLaunchConfig(path); got.Code != "123456" || got.Server != "http://localhost:3000" {
		t.Fatal("launch configuration not parsed")
	}
	footer[0] = 255
	os.WriteFile(path, append([]byte("MZ"), footer...), 0600)
	if got := readLaunchConfig(path); got.Code != "" {
		t.Fatal("malformed footer accepted")
	}
}

func TestGuidedSelectionCancellationAndLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanSelection(ctx, t.TempDir(), false, nil); err != context.Canceled {
		t.Fatal("cancelled scan continued")
	}
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "oversized.bin"))
	if err != nil {
		t.Fatal(err)
	}
	file.Truncate(maxSize + 1)
	file.Close()
	report, err := scanSelection(context.Background(), dir, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].SHA256 != "" || !report.CoverageLimited {
		t.Fatal("oversized file was not explicitly excluded")
	}
}
