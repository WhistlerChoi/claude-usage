package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var errNoCreds = errors.New("Could not read credentials. Log in with Claude Code.")

var mdatRe = regexp.MustCompile(`"mdat"<timedate>=(.+)`)

// extractKeychainMdat captures the raw "mdat" (modification date) line from
// `security find-generic-password` attribute output. "" if absent.
func extractKeychainMdat(output string) string {
	if m := mdatRe.FindStringSubmatch(output); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func credentialsFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", ".credentials.json")
}

// readFingerprint returns a prompt-free change fingerprint of the credential
// store: file mtime if the credentials file exists, otherwise the keychain
// item's mdat attribute (attribute-only read, never triggers an ACL prompt).
// "" means no credentials are present. The source prefix makes a
// file<->keychain transition register as a change.
func readFingerprint() string {
	if path := credentialsFilePath(); path != "" {
		if fi, err := os.Stat(path); err == nil {
			return fmt.Sprintf("file:%d", fi.ModTime().UnixNano())
		}
	}
	if runtime.GOOS == "darwin" {
		// No -w: attributes only.
		out, err := exec.Command("security", "find-generic-password", "-s", "Claude Code-credentials").Output()
		if err == nil {
			if mdat := extractKeychainMdat(string(out)); mdat != "" {
				return "keychain:" + mdat
			}
		}
	}
	return ""
}

func extractToken(b []byte) string {
	var c struct {
		ClaudeAiOauth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
		AccessToken string `json:"accessToken"`
	}
	if json.Unmarshal(b, &c) == nil {
		if c.ClaudeAiOauth.AccessToken != "" {
			return c.ClaudeAiOauth.AccessToken
		}
		if c.AccessToken != "" {
			return c.AccessToken
		}
	}
	return ""
}

// readAccessToken: prefer ~/.claude/.credentials.json (Windows/Linux/macOS); on macOS fall back to the keychain if absent.
func readAccessToken() (string, error) {
	if path := credentialsFilePath(); path != "" {
		if b, e := os.ReadFile(path); e == nil {
			if t := extractToken(b); t != "" {
				return t, nil
			}
		}
	}
	if runtime.GOOS == "darwin" {
		out, e := exec.Command("security", "find-generic-password", "-s", "Claude Code-credentials", "-w").Output()
		if e == nil {
			if t := extractToken(out); t != "" {
				return t, nil
			}
		}
	}
	return "", errNoCreds
}
