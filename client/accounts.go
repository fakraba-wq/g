package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

type account struct {
	Platform string `json:"platform"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Source   string `json:"source"`
}

var discordIDPattern = regexp.MustCompile(`^[0-9]{17,20}$`)

func validDiscordID(id string) bool { return discordIDPattern.MatchString(id) }

// Tokenize Valve's text key/value format. Only the users block, profile IDs and
// PersonaName are returned; login names and all auth-related values are discarded.
func parseSteamProfiles(data []byte) ([]account, error) {
	if len(data) > 1024*1024 {
		return nil, fmt.Errorf("profile metadata exceeds limit")
	}
	input := string(data)
	tokens := []string{}
	for i := 0; i < len(input); {
		c := input[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if c == '/' && i+1 < len(input) && input[i+1] == '/' {
			for i < len(input) && input[i] != '\n' {
				i++
			}
			continue
		}
		if c == '{' || c == '}' {
			tokens = append(tokens, string(c))
			i++
			continue
		}
		if c != '"' {
			return nil, fmt.Errorf("invalid profile metadata")
		}
		i++
		var value strings.Builder
		closed := false
		for i < len(input) {
			c = input[i]
			i++
			if c == '"' {
				closed = true
				break
			}
			if c == '\\' && i < len(input) {
				if input[i] == '"' || input[i] == '\\' {
					c = input[i]
					i++
				}
			}
			value.WriteByte(c)
		}
		if !closed {
			return nil, fmt.Errorf("truncated profile metadata")
		}
		tokens = append(tokens, value.String())
		if len(tokens) > 50000 {
			return nil, fmt.Errorf("profile metadata exceeds token limit")
		}
	}
	type node map[string]any
	pos := 0
	var parse func(int) (node, error)
	parse = func(depth int) (node, error) {
		if depth > 8 {
			return nil, fmt.Errorf("metadata nesting exceeds limit")
		}
		n := node{}
		for pos < len(tokens) {
			key := tokens[pos]
			pos++
			if key == "}" {
				if depth == 0 {
					return nil, fmt.Errorf("invalid metadata block")
				}
				return n, nil
			}
			if key == "{" || pos >= len(tokens) {
				return nil, fmt.Errorf("incomplete metadata")
			}
			value := tokens[pos]
			pos++
			if value == "{" {
				child, err := parse(depth + 1)
				if err != nil {
					return nil, err
				}
				n[key] = child
			} else if value == "}" {
				return nil, fmt.Errorf("invalid metadata value")
			} else {
				n[key] = value
			}
		}
		if depth > 0 {
			return nil, fmt.Errorf("unterminated metadata block")
		}
		return n, nil
	}
	parsed, err := parse(0)
	if err != nil {
		return nil, err
	}
	users, ok := parsed["users"].(node)
	if !ok {
		return nil, fmt.Errorf("users metadata missing")
	}
	profiles := []account{}
	for id, value := range users {
		if !regexp.MustCompile(`^7656[0-9]{13}$`).MatchString(id) {
			continue
		}
		item, ok := value.(node)
		if !ok {
			continue
		}
		name, _ := item["PersonaName"].(string)
		if name == "" {
			name = "Steam profile"
		}
		name = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, name)
		if len(name) > 200 {
			name = name[:200]
		}
		profiles = append(profiles, account{Platform: "steam", ID: id, Name: name, Source: "steam-local-profile"})
		if len(profiles) >= 50 {
			break
		}
	}
	return profiles, nil
}
func steamAccounts() ([]account, bool) {
	results := []account{}
	limited := false
	seen := map[string]bool{}
	for _, root := range steamRoots() {
		if !localInputPath(root) {
			limited = true
			continue
		}
		path := filepath.Join(root, "config", "loginusers.vdf")
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() || info.Size() > 1024*1024 || unsafeLink(path, info) || unsafeLink(filepath.Dir(path), nil) || unsafeLink(root, nil) {
			limited = true
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			limited = true
			continue
		}
		data, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		file.Close()
		if err != nil {
			limited = true
			continue
		}
		rows, err := parseSteamProfiles(data)
		if err != nil {
			limited = true
			continue
		}
		for _, row := range rows {
			if !seen[row.ID] {
				seen[row.ID] = true
				results = append(results, row)
			}
		}
		if len(results) >= 50 {
			return results[:50], true
		}
	}
	return results, limited
}
