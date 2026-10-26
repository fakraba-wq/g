package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxSize int64 = 200 * 1024 * 1024
const maxFiles = 1000

type entry struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Origin    string `json:"origin"`
	ProcessID uint32 `json:"processId,omitempty"`
}
type processFile struct {
	Path string
	PID  uint32
}
type scanReport struct {
	Results              []entry  `json:"results"`
	CoverageLimited      bool     `json:"coverageLimited"`
	ProcessScanRequested bool     `json:"processScanRequested"`
	ProcessScanLimited   bool     `json:"processScanLimited"`
	CoverageNotes        []string `json:"coverageNotes,omitempty"`
}
type session struct {
	SessionID   string `json:"sessionId"`
	UploadToken string `json:"uploadToken"`
}

func inspect(path, origin string, pid uint32) entry {
	return inspectContext(context.Background(), path, origin, pid)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func inspectContext(ctx context.Context, path, origin string, pid uint32) entry {
	result := entry{Name: filepath.Base(path), Origin: origin, ProcessID: pid}
	f, err := os.Open(path)
	if err != nil {
		result.Reason = "Unable to open file"
		return result
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		result.Reason = "Not a readable regular file"
		return result
	}
	result.Size = before.Size()
	if result.Size > maxSize {
		result.Reason = "Over 200 MB"
		return result
	}
	hash := sha256.New()
	count, err := io.Copy(hash, contextReader{ctx: ctx, reader: io.LimitReader(f, maxSize+1)})
	if err != nil {
		result.Reason = "Unable to read file"
		return result
	}
	after, err := f.Stat()
	if err != nil || count != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		result.Reason = "File changed during check"
		return result
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result
}

func collectFolder(root string, report *scanReport) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("select a regular, accessible folder")
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			report.CoverageLimited = true
			return nil
		}
		if len(report.Results) >= maxFiles {
			report.CoverageLimited = true
			return filepath.SkipAll
		}
		if d.Type()&os.ModeSymlink != 0 {
			report.CoverageLimited = true
			return nil
		}
		if d.IsDir() {
			return nil
		}
		result := inspect(path, "selected-folder", 0)
		if result.SHA256 == "" {
			report.CoverageLimited = true
		}
		report.Results = append(report.Results, result)
		fmt.Printf("\rFiles processed: %d", len(report.Results))
		return nil
	})
}

func validateServer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("enter a server origin, for example https://check.example.com")
	}
	local := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		local = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return "", errors.New("HTTPS is required except on localhost")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func post(client *http.Client, target, token string, payload any, output any) error {
	return postContext(context.Background(), client, target, token, payload, output)
}
func postContext(ctx context.Context, client *http.Client, target, token string, payload any, output any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
		if body.Error == "" {
			body.Error = resp.Status
		}
		return errors.New(body.Error)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(output)
	}
	return nil
}

func runCLI(serverInput, codeInput string) error {
	input := bufio.NewReader(os.Stdin)
	ask := func(prompt string) string {
		fmt.Print(prompt + ": ")
		line, _ := input.ReadString('\n')
		return strings.TrimSpace(line)
	}
	fmt.Println("CRIMSON PC CHECK / WINDOWS FILE & PROCESS CHECK")
	fmt.Println("Checks selected folder files and, optionally, readable running executable files.")
	fmt.Println("No process memory, deleted files, browser history, credentials or registry are collected.")
	fmt.Println("No elevation or persistence. This tool is not proof of a cheat-free PC.")
	raw := serverInput
	if raw == "" {
		raw = ask("Staff server URL")
	}
	server, err := validateServer(raw)
	if err != nil {
		return err
	}
	code := codeInput
	if code == "" {
		code = ask("Six-digit session code")
	}
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return errors.New("invalid session code")
	}
	folder := strings.Trim(ask("Folder path to inspect (leave blank for processes only)"), "\"")
	processConsent := strings.EqualFold(ask("Also hash accessible running executable files? Type PROCESSES to opt in"), "PROCESSES")
	if folder == "" && !processConsent {
		return errors.New("nothing selected for inspection")
	}
	fmt.Println("Only filenames, sizes, hashes, origin and (if opted in) process IDs may be shared.")
	if !strings.EqualFold(ask("I own these files or have permission and want to scan. Type YES"), "YES") {
		fmt.Println("Cancelled. Nothing scanned or sent.")
		return nil
	}
	if folder != "" {
		info, err := os.Lstat(folder)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("select a regular, accessible folder")
		}
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return errors.New("redirect refused; use the final HTTPS server URL")
	}}
	var s session
	if err = post(client, server+"/api/sessions/redeem", "", map[string]string{"code": code}, &s); err != nil {
		return err
	}
	if len(s.SessionID) != 36 || len(s.UploadToken) != 64 || strings.ContainsAny(s.SessionID, "/\\") {
		return errors.New("invalid session response")
	}
	report := scanReport{Results: []entry{}, ProcessScanRequested: processConsent}
	if folder != "" {
		if err = collectFolder(folder, &report); err != nil {
			return err
		}
		fmt.Println()
	}
	if processConsent {
		processes, limited, processErr := runningFiles()
		report.ProcessScanLimited = limited || processErr != nil
		seen := map[string]bool{}
		for _, p := range processes {
			key := strings.ToLower(p.Path)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(report.Results) >= maxFiles {
				report.ProcessScanLimited = true
				break
			}
			result := inspect(p.Path, "running-process", p.PID)
			if result.SHA256 == "" {
				report.ProcessScanLimited = true
			}
			report.Results = append(report.Results, result)
		}
		if processErr != nil {
			fmt.Println("Process inspection was unavailable:", processErr)
		}
		report.CoverageLimited = report.CoverageLimited || report.ProcessScanLimited
	}
	if len(report.Results) == 0 {
		return errors.New("no file entries could be collected; no report submitted")
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	local, err := os.CreateTemp("", "crimson-report-*.json")
	if err != nil {
		return err
	}
	if _, err = local.Write(data); err != nil {
		local.Close()
		return err
	}
	if err = local.Close(); err != nil {
		return err
	}
	fmt.Println("Review your local report:", local.Name())
	fmt.Printf("%d file entries. Coverage limited: %v. No file contents are included.\n", len(report.Results), report.CoverageLimited)
	if !strings.EqualFold(ask("Send this report to "+server+" for staff review? Type SEND"), "SEND") {
		fmt.Println("Not sent. Your report stays local.")
		return nil
	}
	if err = post(client, server+"/api/sessions/"+s.SessionID+"/report", s.UploadToken, report, nil); err != nil {
		return err
	}
	fmt.Println("Report submitted. Staff can review the results.")
	return nil
}
