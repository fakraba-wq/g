package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryFiltersAndBounds(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	os.Mkdir(nested, 0700)
	for _, name := range []string{"one.exe", "two.DLL", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(nested, name), []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "outside.exe"), []byte("outside"), 0600)
	os.Symlink(outside, filepath.Join(root, "junction"))
	paths := []string{}
	count, _, err := discoverFiles(context.Background(), []scanRoot{{"fixture", root}}, 10, func(path string) { paths = append(paths, path) })
	if err != nil || count != 2 || len(paths) != 2 {
		t.Fatalf("wrong selection: %v %v", paths, err)
	}
	count, limited, err := discoverFiles(context.Background(), []scanRoot{{"fixture", root}}, 1, func(string) {})
	if err != nil || count != 1 || !limited {
		t.Fatalf("file cap not enforced: %d %v %v", count, limited, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err = discoverFiles(ctx, []scanRoot{{"fixture", root}}, 10, func(string) {}); err != context.Canceled {
		t.Fatal("cancel ignored", err)
	}
}
func TestAutomaticDiscoveryAndPathConsent(t *testing.T) {
	local := t.TempDir()
	folder := filepath.Join(local, "Temp", "nested")
	os.MkdirAll(folder, 0700)
	os.WriteFile(filepath.Join(folder, "fixture.exe"), []byte("hello"), 0600)
	t.Setenv("LOCALAPPDATA", local)
	for _, paths := range []bool{false, true} {
		report, err := scanWithOptions(context.Background(), "", scanOptions{Discovery: true, Paths: paths, Accounts: true, DiscordID: "10000000000000000"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, file := range report.Results {
			if file.Name == "fixture.exe" {
				found = true
				if (file.Path != "") != paths {
					t.Fatal("path consent ignored")
				}
			}
		}
		if !found {
			t.Fatal("automatic location missed known fixture")
		}
		if !paths && len(report.Evidence.Roots) > 0 {
			t.Fatal("unconsented root paths retained")
		}
		if len(report.Evidence.Accounts) < 1 || report.Evidence.Accounts[len(report.Evidence.Accounts)-1].Source != "player-provided" {
			t.Fatal("explicit profile ID missing")
		}
	}
	report, err := scanWithOptions(context.Background(), folder, scanOptions{DiscordID: "10000000000000000"}, nil)
	if err != nil || len(report.Evidence.Accounts) != 0 || report.Options.DiscordID != "" {
		t.Fatal("unconsented profile collected")
	}
}
func TestSteamProfilesExcludeAuthMetadata(t *testing.T) {
	data := []byte(`"users" { "76561198000000001" { "AccountName" "private-login" "PersonaName" "Fixture persona" "RememberPassword" "1" "SomeUnexpectedToken" "secret-fixture" } }`)
	profiles, err := parseSteamProfiles(data)
	if err != nil || len(profiles) != 1 || profiles[0].Name != "Fixture persona" || profiles[0].Source != "steam-local-profile" {
		t.Fatalf("invalid profile: %v %v", profiles, err)
	}
	if _, err = parseSteamProfiles([]byte(`"users" { "76561198000000001" {`)); err == nil {
		t.Fatal("truncated profile block accepted")
	}
	if validDiscordID("token-secret") || validDiscordID("123") || !validDiscordID("10000000000000000") {
		t.Fatal("profile ID validation failed")
	}
}
