package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type scanRoot struct {
	Label string `json:"label"`
	Path  string `json:"path"`
}

// Fixed locations belonging to the current Windows user; never whole drives or network roots.
func standardRoots() []scanRoot {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := []scanRoot{{"Bureau", filepath.Join(home, "Desktop")}, {"Téléchargements", filepath.Join(home, "Downloads")}, {"Documents", filepath.Join(home, "Documents")}}
	if one := os.Getenv("OneDrive"); one != "" {
		candidates = append(candidates, scanRoot{"Bureau OneDrive", filepath.Join(one, "Desktop")}, scanRoot{"Documents OneDrive", filepath.Join(one, "Documents")})
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		candidates = append(candidates, scanRoot{"Temp utilisateur", filepath.Join(local, "Temp")}, scanRoot{"FiveM", filepath.Join(local, "FiveM", "FiveM.app")})
	}
	roots := []scanRoot{}
	seen := map[string]bool{}
	for _, root := range candidates {
		key := strings.ToLower(filepath.Clean(root.Path))
		if seen[key] || !localInputPath(root.Path) {
			continue
		}
		info, err := os.Lstat(root.Path)
		if err != nil || !info.IsDir() || unsafeLink(root.Path, info) {
			continue
		}
		seen[key] = true
		roots = append(roots, root)
	}
	return roots
}
func discoverFiles(ctx context.Context, roots []scanRoot, remaining int, consume func(string)) (int, bool, error) {
	count, visited := 0, 0
	limited := false
	deadline := time.Now().Add(2 * time.Minute)
	seen := map[string]bool{}
	for _, root := range roots {
		if !localInputPath(root.Path) {
			limited = true
			continue
		}
		info, err := os.Lstat(root.Path)
		if err != nil || !info.IsDir() || unsafeLink(root.Path, info) {
			limited = true
			continue
		}
		err = filepath.WalkDir(root.Path, func(path string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if count >= remaining || visited >= 50000 || time.Now().After(deadline) {
				limited = true
				return filepath.SkipAll
			}
			visited++
			if walkErr != nil {
				limited = true
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 || unsafeLink(path, nil) {
				limited = true
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(root.Path, path)
			if d.IsDir() {
				if strings.Count(rel, string(filepath.Separator)) >= 8 {
					limited = true
					return filepath.SkipDir
				}
				if d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "Cache" || d.Name() == "cache" || d.Name() == "cache2" {
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".exe" && ext != ".dll" {
				return nil
			}
			key := strings.ToLower(filepath.Clean(path))
			if seen[key] {
				return nil
			}
			seen[key] = true
			consume(path)
			count++
			return nil
		})
		if err != nil {
			return count, true, err
		}
		if count >= remaining || visited >= 50000 || time.Now().After(deadline) {
			limited = true
			break
		}
	}
	return count, limited, nil
}
