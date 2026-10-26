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
	report := scanReport{Results: []entry{}, ProcessScanRequested: processes}
	add := func(result entry) {
		report.Results = append(report.Results, result)
		if result.SHA256 == "" {
			report.CoverageLimited = true
		}
		if progress != nil {
			progress(len(report.Results))
		}
	}
	if folder != "" {
		info, err := os.Lstat(folder)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
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
			if d.Type()&os.ModeSymlink != 0 {
				report.CoverageLimited = true
				return nil
			}
			if d.IsDir() {
				return nil
			}
			add(inspectContext(ctx, path, "selected-folder", 0))
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
			result := inspectContext(ctx, p.Path, "running-process", p.PID)
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
	if len(report.Results) == 0 {
		return report, errors.New("aucun fichier accessible; choisissez un dossier ou activez les processus sur Windows")
	}
	return report, nil
}
