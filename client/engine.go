package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func scanSelection(ctx context.Context, folder string, processes bool, progress func(int)) (scanReport, error) {
	return scanWithOptions(ctx, folder, scanOptions{Processes: processes}, progress)
}
func scanWithOptions(ctx context.Context, folder string, options scanOptions, progress func(int)) (scanReport, error) {
	if !options.Accounts {
		options.DiscordID = ""
	}
	processes := options.Processes
	report := scanReport{Results: []entry{}, ProcessScanRequested: processes, Options: options}
	seenPaths := map[string]bool{}
	add := func(result entry) {
		if result.sourcePath != "" {
			key := strings.ToLower(result.sourcePath)
			if seenPaths[key] {
				return
			}
			seenPaths[key] = true
		}
		if !options.Paths {
			result.Path = ""
		}
		report.Results = append(report.Results, result)
		if result.SHA256 == "" {
			report.CoverageLimited = true
		}
		if progress != nil {
			progress(len(report.Results))
		}
	}
	if folder != "" {
		if !localInputPath(folder) {
			return report, errors.New("choisissez un dossier sur un volume local")
		}
		info, err := os.Lstat(folder)
		if err != nil || !info.IsDir() || unsafeLink(folder, info) {
			return report, errors.New("dossier introuvable ou inaccessible")
		}
		err = filepath.WalkDir(folder, func(path string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				report.CoverageLimited = true
				return nil
			}
			if len(report.Results) >= maxFiles {
				report.CoverageLimited = true
				return filepath.SkipAll
			}
			if d.Type()&os.ModeSymlink != 0 || unsafeLink(path, nil) {
				report.CoverageLimited = true
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			item := inspectEnriched(ctx, path, "selected-folder", 0, options.Integrity)
			if options.Paths {
				item.Path = path
			}
			add(item)
			return nil
		})
		if err != nil {
			return report, err
		}
		if report.CoverageLimited {
			report.CoverageNotes = append(report.CoverageNotes, "folder-access-limited")
		}
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if processes {
		paths, limited, err := runningFiles()
		report.ProcessScanLimited = limited || err != nil
		seen := map[string]bool{}
		for _, p := range paths {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			key := strings.ToLower(p.Path)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(report.Results) >= maxFiles {
				report.ProcessScanLimited = true
				break
			}
			result := inspectEnriched(ctx, p.Path, "running-process", p.PID, options.Integrity)
			if options.Paths {
				result.Path = p.Path
			}
			if result.SHA256 == "" {
				report.ProcessScanLimited = true
			}
			add(result)
		}
		if report.ProcessScanLimited {
			report.CoverageLimited = true
			report.CoverageNotes = append(report.CoverageNotes, "process-access-limited")
		}
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if options.Modules {
		modules, limited, err := gameModules()
		if err != nil {
			limited = true
		}
		count := 0
		seen := map[string]bool{}
		for _, module := range modules {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			key := strings.ToLower(module.Path)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(report.Results) >= maxFiles {
				limited = true
				break
			}
			item := inspectEnriched(ctx, module.Path, "loaded-module", module.PID, options.Integrity)
			if options.Paths {
				item.Path = module.Path
			}
			if item.SHA256 == "" {
				limited = true
			}
			add(item)
			count++
		}
		state := "collected"
		if limited {
			state = "partial"
			report.CoverageLimited = true
		}
		if err != nil {
			state = "unavailable"
		}
		report.Evidence.Collection = append(report.Evidence.Collection, collection{Key: "modules", State: state, Count: count, Note: "Accessible DLL image files listed for FiveM/GTA processes only; no process memory dump."})
	} else {
		report.Evidence.Collection = append(report.Evidence.Collection, collection{Key: "modules", State: "not-requested", Note: "Not authorized in this scan."})
	}
	if options.Discovery {
		roots := standardRoots()
		if options.Paths {
			report.Evidence.Roots = roots
		}
		beforeDiscovery := len(report.Results)
		_, limited, err := discoverFiles(ctx, roots, maxFiles-len(report.Results), func(path string) {
			item := inspectEnriched(ctx, path, "standard-location", 0, options.Integrity)
			if options.Paths {
				item.Path = path
			}
			add(item)
		})
		if err != nil {
			return report, err
		}
		state := "collected"
		if len(roots) == 0 {
			state = "unavailable"
			limited = true
		}
		if limited && state != "unavailable" {
			state = "partial"
		}
		report.CoverageLimited = report.CoverageLimited || limited
		report.Evidence.Collection = append(report.Evidence.Collection, collection{Key: "discovery", State: state, Count: len(report.Results) - beforeDiscovery, Note: "EXE/DLL in listed current-user locations only; 1000 total files, 50000 directory entries, depth 8 and two-minute discovery limit. Links, network locations and cache directories excluded."})
	} else {
		report.Evidence.Collection = append(report.Evidence.Collection, collection{Key: "discovery", State: "not-requested", Note: "Standard locations not authorized."})
	}
	if options.Accounts {
		accounts, limited := steamAccounts()
		report.Evidence.Accounts = accounts
		if validDiscordID(options.DiscordID) {
			report.Evidence.Accounts = append(report.Evidence.Accounts, account{Platform: "discord", ID: options.DiscordID, Name: "Discord ID supplied by player", Source: "player-provided"})
		}
		state := "collected"
		if limited {
			state = "partial"
		}
		if len(accounts) == 0 && options.DiscordID == "" {
			state = "unavailable"
		}
		report.Evidence.Collection = append(report.Evidence.Collection, collection{Key: "accounts", State: state, Count: len(report.Evidence.Accounts), Note: "Steam locally remembered profile identifiers and optional player-provided Discord ID; not verified ownership or a complete account inventory. No tokens, passwords or session files."})
	}
	system := systemEvidence(ctx, options.Boot, options.Activity)
	report.Evidence.Boot = system.Boot
	report.Evidence.Executions = system.Executions
	if !options.Paths {
		for i := range report.Evidence.Executions {
			report.Evidence.Executions[i].Path = ""
		}
	}
	report.Evidence.WindowStartUTC = system.WindowStartUTC
	report.Evidence.Collection = append(report.Evidence.Collection, system.Collection...)
	for _, status := range system.Collection {
		if status.State == "partial" || status.State == "unavailable" {
			report.CoverageLimited = true
		}
	}
	count := 0
	for _, file := range report.Results {
		if file.PE != nil {
			count++
		}
	}
	state := "not-requested"
	if options.Integrity {
		state = "collected"
	}
	report.Evidence.Collection = append(report.Evidence.Collection, collection{Key: "integrity", State: state, Count: count, Note: "PE header timestamps and cache-only Windows trust checks; unsigned files are not automatically cheats."})
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if len(report.Results) == 0 && !options.Boot && !options.Activity && !options.Modules && !options.Discovery && !options.Accounts {
		return report, errors.New("aucun fichier accessible; choisissez un dossier ou activez les processus sur Windows")
	}
	return report, nil
}
