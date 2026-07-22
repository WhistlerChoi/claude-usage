package main

import (
	"errors"
	"os"
)

var errKeychainDenied = errors.New("Keychain access denied. Use Refresh Now to try again.")

// credCache caches the access token so the secret store (macOS keychain /
// credentials file) is read at most once per change. Every Get() does a
// prompt-free fingerprint read; the secret is re-read only when the
// fingerprint changes, capping keychain ACL prompts at roughly one per
// Claude Code token rotation instead of one per poll.
type credCache struct {
	envToken   func() string
	readFP     func() string // "" = no credentials present
	readSecret func() (string, error)

	token        string
	hasToken     bool
	fp           string
	rejectedFP   string
	hasRejected  bool
	rejectionErr error
}

func newCredCache() *credCache {
	return &credCache{
		envToken:   func() string { return os.Getenv("CLAUDE_USAGE_TOKEN") },
		readFP:     readFingerprint,
		readSecret: readAccessToken,
	}
}

// Get returns the current access token. force bypasses only a previous
// rejection (an explicit user retry may prompt once); a healthy cached token
// is returned without any secret read.
func (c *credCache) Get(force bool) (string, error) {
	if t := c.envToken(); t != "" {
		return t, nil
	}

	fp := c.readFP()

	if c.hasToken && fp == c.fp {
		return c.token, nil
	}

	if fp == "" {
		c.hasToken = false
		c.fp = ""
		return "", errNoCreds
	}

	if !force && c.hasRejected && fp == c.rejectedFP {
		return "", c.rejectionErr
	}

	token, err := c.readSecret()
	if err != nil {
		c.hasToken = false
		c.rejectedFP = fp
		c.hasRejected = true
		c.rejectionErr = errKeychainDenied
		return "", errKeychainDenied
	}
	c.token = token
	c.hasToken = true
	c.fp = fp
	c.hasRejected = false
	return token, nil
}

// Invalidate marks the cached token as rejected by the API (HTTP 401/403).
func (c *credCache) Invalidate() {
	c.hasToken = false
	c.rejectedFP = c.fp
	c.hasRejected = true
	c.rejectionErr = errAuth
}
