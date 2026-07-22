package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

var errAuth = errors.New("Authentication expired. Log in again.")

// transientError: a retryable error (network/5xx/429 etc.). retryAfter is the 429 Retry-After (seconds).
type transientError struct {
	msg        string
	retryAfter time.Duration
}

func (e *transientError) Error() string { return e.msg }

// retryAfterFrom: the retryAfter if err is a transientError, otherwise 0.
func retryAfterFrom(err error) time.Duration {
	var te *transientError
	if errors.As(err, &te) {
		return te.retryAfter
	}
	return 0
}

// parseRetryAfter: convert an integer-seconds header to a Duration. Non-integer/empty is 0.
func parseRetryAfter(h string) time.Duration {
	if n, err := strconv.Atoi(h); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

type window struct {
	Utilization float64 `json:"utilization"` // 0~100 (percent)
	ResetsAt    *string `json:"resets_at"`
}

type usageResp struct {
	FiveHour       *window `json:"five_hour"`
	SevenDay       *window `json:"seven_day"`
	SevenDayOpus   *window `json:"seven_day_opus"`
	SevenDaySonnet *window `json:"seven_day_sonnet"`
}

// fetchUsage fetches current usage. On 401/403 the cached token is
// invalidated and, if the credential store already holds a different token
// (Claude Code rotated it), the request is retried exactly once.
// Strictly read-only: never refreshes or writes tokens.
func fetchUsage(cache *credCache, force bool) (*usageResp, error) {
	token, err := cache.Get(force)
	if err != nil {
		return nil, err
	}
	u, err := requestUsage(token)
	if !errors.Is(err, errAuth) {
		return u, err
	}

	cache.Invalidate()
	retryToken, err := cache.Get(false)
	if err != nil || retryToken == token {
		return nil, errAuth
	}
	u, err = requestUsage(retryToken)
	if errors.Is(err, errAuth) {
		cache.Invalidate()
	}
	return u, err
}

func requestUsage(token string) (*usageResp, error) {
	req, _ := http.NewRequest("GET", "https://api.anthropic.com/api/oauth/usage", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, errAuth
	}
	if resp.StatusCode == 429 {
		return nil, &transientError{
			msg:        "network error",
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &transientError{msg: fmt.Sprintf("network error: HTTP %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var u usageResp
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	}
	if u.FiveHour == nil || u.SevenDay == nil {
		return nil, errors.New("invalid usage response format")
	}
	return &u, nil
}
