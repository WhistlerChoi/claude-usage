package main

import (
	"errors"
	"strings"
	"testing"
)

type fakeCredState struct {
	fp          string
	secret      string
	secretErr   error
	fpReads     int
	secretReads int
}

func newFakeCache(st *fakeCredState, env string) *credCache {
	return &credCache{
		envToken: func() string { return env },
		readFP: func() string {
			st.fpReads++
			return st.fp
		},
		readSecret: func() (string, error) {
			st.secretReads++
			if st.secretErr != nil {
				return "", st.secretErr
			}
			return st.secret, nil
		},
	}
}

func TestSteadyStateReadsSecretOnce(t *testing.T) {
	st := &fakeCredState{fp: "keychain:A", secret: "tok-1"}
	c := newFakeCache(st, "")
	for i := 0; i < 3; i++ {
		tok, err := c.Get(false)
		if err != nil || tok != "tok-1" {
			t.Fatalf("Get: %v %v", tok, err)
		}
	}
	if st.secretReads != 1 {
		t.Fatalf("secretReads = %d, want 1", st.secretReads)
	}
	if st.fpReads != 3 {
		t.Fatalf("fpReads = %d, want 3", st.fpReads)
	}
}

func TestFingerprintChangeRereadsOnce(t *testing.T) {
	st := &fakeCredState{fp: "keychain:A", secret: "tok-1"}
	c := newFakeCache(st, "")
	c.Get(false)
	st.fp, st.secret = "keychain:B", "tok-2"
	tok, err := c.Get(false)
	if err != nil || tok != "tok-2" {
		t.Fatalf("Get after change: %v %v", tok, err)
	}
	c.Get(false)
	if st.secretReads != 2 {
		t.Fatalf("secretReads = %d, want 2", st.secretReads)
	}
}

func TestInvalidateUnchangedFingerprintSkipsSecret(t *testing.T) {
	st := &fakeCredState{fp: "keychain:A", secret: "tok-1"}
	c := newFakeCache(st, "")
	c.Get(false)
	c.Invalidate()
	if _, err := c.Get(false); !errors.Is(err, errAuth) {
		t.Fatalf("want errAuth, got %v", err)
	}
	if _, err := c.Get(false); err == nil {
		t.Fatal("want error on second call")
	}
	if st.secretReads != 1 {
		t.Fatalf("secretReads = %d, want 1", st.secretReads)
	}
}

func TestInvalidateChangedFingerprintRereads(t *testing.T) {
	st := &fakeCredState{fp: "keychain:A", secret: "tok-1"}
	c := newFakeCache(st, "")
	c.Get(false)
	c.Invalidate()
	st.fp, st.secret = "keychain:B", "tok-2"
	tok, err := c.Get(false)
	if err != nil || tok != "tok-2" {
		t.Fatalf("Get: %v %v", tok, err)
	}
}

func TestDeniedReadNoRetryUntilForce(t *testing.T) {
	st := &fakeCredState{fp: "keychain:A", secretErr: errNoCreds}
	c := newFakeCache(st, "")
	if _, err := c.Get(false); !errors.Is(err, errKeychainDenied) {
		t.Fatalf("want errKeychainDenied, got %v", err)
	}
	c.Get(false)
	c.Get(false)
	if st.secretReads != 1 {
		t.Fatalf("secretReads = %d, want 1", st.secretReads)
	}
	st.secretErr, st.secret = nil, "tok-1"
	tok, err := c.Get(true)
	if err != nil || tok != "tok-1" {
		t.Fatalf("forced Get: %v %v", tok, err)
	}
	if st.secretReads != 2 {
		t.Fatalf("secretReads = %d, want 2", st.secretReads)
	}
}

func TestEmptyFingerprintLoginNeededThenRecovers(t *testing.T) {
	st := &fakeCredState{fp: "", secret: "tok-1"}
	c := newFakeCache(st, "")
	if _, err := c.Get(false); !errors.Is(err, errNoCreds) {
		t.Fatalf("want errNoCreds, got %v", err)
	}
	if st.secretReads != 0 {
		t.Fatalf("secretReads = %d, want 0", st.secretReads)
	}
	st.fp = "keychain:A"
	tok, err := c.Get(false)
	if err != nil || tok != "tok-1" {
		t.Fatalf("Get after creds appear: %v %v", tok, err)
	}
}

func TestSourceTransitionCountsAsChange(t *testing.T) {
	st := &fakeCredState{fp: "file:1000", secret: "tok-file"}
	c := newFakeCache(st, "")
	c.Get(false)
	st.fp, st.secret = "keychain:1000", "tok-keychain"
	tok, err := c.Get(false)
	if err != nil || tok != "tok-keychain" {
		t.Fatalf("Get: %v %v", tok, err)
	}
	if st.secretReads != 2 {
		t.Fatalf("secretReads = %d, want 2", st.secretReads)
	}
}

func TestEnvTokenBypassesSource(t *testing.T) {
	st := &fakeCredState{fp: "keychain:A", secret: "tok-1"}
	c := newFakeCache(st, "tok-env")
	tok, err := c.Get(false)
	if err != nil || tok != "tok-env" {
		t.Fatalf("Get: %v %v", tok, err)
	}
	if st.fpReads != 0 || st.secretReads != 0 {
		t.Fatalf("source touched: fp=%d secret=%d", st.fpReads, st.secretReads)
	}
}

func TestForceDoesNotBypassHealthyCache(t *testing.T) {
	st := &fakeCredState{fp: "keychain:A", secret: "tok-1"}
	c := newFakeCache(st, "")
	c.Get(false)
	tok, err := c.Get(true)
	if err != nil || tok != "tok-1" {
		t.Fatalf("forced Get: %v %v", tok, err)
	}
	if st.secretReads != 1 {
		t.Fatalf("secretReads = %d, want 1", st.secretReads)
	}
}

const realCliOutput = `keychain: "/Users/whistler/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="Claude Code-credentials"
    "acct"<blob>="whistler"
    "cdat"<timedate>=0x32303236303732323031323533305A00  "20260722012530Z\000"
    "mdat"<timedate>=0x32303236303732323031323535375A00  "20260722012557Z\000"
    "svce"<blob>="Claude Code-credentials"
`

func TestExtractKeychainMdat(t *testing.T) {
	mdat := extractKeychainMdat(realCliOutput)
	if mdat == "" {
		t.Fatal("mdat not found")
	}
	if !strings.Contains(mdat, "0x32303236303732323031323535375A00") || !strings.Contains(mdat, "20260722012557Z") {
		t.Fatalf("unexpected mdat: %q", mdat)
	}
	if extractKeychainMdat("no attributes here\n") != "" {
		t.Fatal("want empty for missing mdat")
	}
}
