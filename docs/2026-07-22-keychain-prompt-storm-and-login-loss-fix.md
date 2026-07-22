# Fix: macOS keychain prompt storm and Claude Code login loss

**Date:** 2026-07-22
**Scope:** all three ports (`src/`, `tray-go/`, `menubar/`)
**Versions:** VSCode extension `0.3.0 → 0.3.1`, macOS app `1.0.0 → 1.0.1`

## Summary

Pulse had two distinct defects on macOS:

1. **Login loss** — the macOS menu-bar port was *writing* to Claude Code's
   credentials. It refreshed the OAuth token using Claude Code's single-use
   refresh token and wrote the result back to the keychain / credentials file.
   Because refresh tokens are single-use, an uncoordinated refresh raced Claude
   Code's own token rotation and revoked the whole token family server-side,
   logging the user out after a reboot or wake. The keychain-write fallback
   (`SecItemAdd`) could also create a Pulse-owned keychain item that Claude Code
   could no longer read, surfacing as *"Failed to retrieve auth status after
   login"* in the VSCode login flow.

2. **Keychain prompt storm** — all three ports read the full keychain secret on
   **every poll** (default 300 s, no caching). The app is ad-hoc signed (no Team
   ID) and the keychain item is ACL-protected by Claude Code, so macOS could not
   persist "Always Allow" and prompted for the login password on every read.
   In the logged-out state the ports retried the secret read every tick, so the
   prompt reappeared indefinitely.

The fix makes every port **strictly read-only** with respect to Claude Code's
credentials and introduces an in-memory credential cache gated on a
**prompt-free change fingerprint**, so the secret is read at most about once per
token rotation instead of once per poll.

## Symptoms (as reported)

- After booting the Mac, Claude Code was logged out.
- A macOS prompt — *"security wants to access key 'Claude Code-credentials' in
  your keychain"* — appeared repeatedly and kept reappearing after entering the
  password.
- Logging in again through the VSCode Claude Code panel failed with *"Failed to
  retrieve auth status after login."*

## Root cause investigation

Diagnosis was done by mapping the credential code paths in all three ports and
inspecting the machine state.

### Evidence

- `~/.claude/.credentials.json` did **not** exist on the machine. On macOS,
  Claude Code stores credentials only in the keychain (item
  `Claude Code-credentials`), so every Pulse poll fell through to the keychain.
- `Pulse.app` was installed as a login item and ad-hoc signed:
  `Signature=adhoc`, `TeamIdentifier=not set`. Ad-hoc signatures have no stable
  designated requirement, so the keychain ACL cannot bind "Always Allow" to the
  app across launches/rebuilds.
- The keychain item's `cdat` (creation date) was the current day — consistent
  with a recent forced re-login and/or a Pulse `SecItemAdd` recreation.
- Claude Code was on v2.1.217; the documented multi-session token-renewal race
  (fixed in v2.1.211) was therefore not the cause here — the write-back in
  Pulse's own code was.

### Credential read paths (before)

| Port | Secret read | Frequency | Writes? |
|---|---|---|---|
| `src/` (TS) | `security find-generic-password -s "Claude Code-credentials" -w` | every poll, no cache | read-only |
| `tray-go/` (Go) | same `security` CLI | every poll, no cache | read-only |
| `menubar/` (Swift) | `SecItemCopyMatching` (returns data) | every poll, no cache | **writes** (refresh + `SecItemUpdate`/`SecItemAdd`, file write-back) |

The Swift write path (`TokenRefresh.swift`, plus the write-back half of
`Credentials.swift` and the auto-refresh logic in `UsageClient.swift`) is what
revoked the login. The uncached per-poll secret read in all three ports is what
produced the prompt storm.

## The fix

### 1. Strictly read-only

- Deleted `menubar/Sources/Pulse/TokenRefresh.swift` entirely.
- Removed all write-back from `Credentials.swift` (`mergedCredentialsData`,
  `writeCredentials`, `SecItemUpdate`/`SecItemAdd`, the `writeFailed` error) and
  dropped the now-unused `refreshToken` / `expiresAtMs` fields.
- Replaced `fetchUsageAutoRefreshing` / `performRefresh` in `UsageClient.swift`
  with a read-only `fetchUsageCached`.
- Verified: `grep -rn "refreshAccessToken|writeCredentials|SecItemUpdate|SecItemAdd|oauthClientID|parseRefreshResponse" menubar/Sources` returns nothing.

Expired tokens are now handled purely by the existing "login needed" contract;
HTTP 401 is the only expiry signal. Pulse never mutates Claude Code's stores.

### 2. Prompt-free change fingerprint

A "fingerprint" is an opaque string that changes when the credentials change,
obtained **without** triggering a keychain ACL prompt:

- File present → `"file:<mtime>"`
- Else macOS keychain item present → `"keychain:<mdat>"`, where `mdat` is the
  item's modification-date attribute read via `security find-generic-password -s
  ... ` **without `-w`** (TS/Go) or `SecItemCopyMatching` with
  `kSecReturnAttributes` and **no** `kSecReturnData` (Swift). Attribute-only
  reads do not prompt — verified empirically on the affected machine.
- Else → `null` (no credentials present)

The source prefix makes a file↔keychain transition register as a change. The raw
value is compared as an opaque string; it is never parsed.

### 3. Credential cache state machine (identical in all three ports)

`getToken(force)`:

1. If `CLAUDE_USAGE_TOKEN` is set → return it (no source access at all).
2. Read the fingerprint (always prompt-free).
3. If a token is cached and the fingerprint is unchanged → return the cached
   token. *(steady state: zero secret reads, zero prompts)*
4. If `!force` and the fingerprint equals the previously **rejected** one →
   throw without reading the secret. *(logged-out/denied state: zero prompts —
   this gate is what actually prevents the storm; a bare "re-read on 401" would
   reintroduce it)*
5. Otherwise do exactly one secret read. Success → cache and clear rejection.
   Failure → record the rejected fingerprint and throw.

`invalidate()` (called on HTTP 401/403): mark the current fingerprint rejected
and drop the cached token.

In `fetchUsage`, a 401/403 invalidates the cache and retries the request **once**
— but only if the store now yields a *different* token (i.e. Claude Code already
rotated it). Otherwise it raises an auth error. This recovers silently across a
token rotation with no writes and no prompt.

"Refresh Now" passes `force = true`, which bypasses **only** the rejection gate
(step 4) — an explicit user retry may prompt once — but never re-reads a healthy
cached token (step 3), so Refresh Now stays prompt-free in the good state.

### 4. Error messages (shared, English)

- No credentials at all → `"Could not read credentials. Log in with Claude Code."`
- Item present but the secret read failed/was denied →
  `"Keychain access denied. Use Refresh Now to try again."`
- API rejected the token (401/403) → `"Authentication expired. Log in again."`

### 5. `CLAUDE_USAGE_TOKEN` escape hatch

If set, Pulse uses that token verbatim and never touches Claude Code's stores —
a fully prompt-free mode (e.g. with a `claude setup-token` long-lived token).
The in-app "set token" UI was intentionally *not* added: whether the usage
endpoint accepts a setup-token bearer token needs an interactive verification
step first, and storing a token in an ad-hoc-signed app's own keychain item
would re-introduce prompts on every rebuild. A plain env var avoids both issues.

## Files changed

- `src/credentials.ts` — added `readFingerprint()` / `extractKeychainMdat()`;
  the secret read is unchanged.
- `src/credentialCache.ts` — **new**, the cache state machine.
- `src/usageClient.ts` — `fetchUsage(force, cache)` with 401 invalidate +
  retry-once.
- `src/extension.ts` — `refresh(force)`; the `pulse.refresh` command forces.
- `src/credentialCache.test.ts`, `src/usageClient.test.ts` — **new** tests.
- `tray-go/creds.go` — added `readFingerprint()` / `extractKeychainMdat()`.
- `tray-go/credcache.go` — **new**, mirror of the cache.
- `tray-go/usage.go` — `fetchUsage(cache, force)` with the same retry contract.
- `tray-go/main.go` — package-level cache; manual refresh forces.
- `tray-go/credcache_test.go` — **new** tests.
- `menubar/Sources/Pulse/TokenRefresh.swift` — **deleted**.
- `menubar/Sources/Pulse/Credentials.swift` — read-only; added `readFingerprint()`.
- `menubar/Sources/Pulse/CredentialCache.swift` — **new**, mirror of the cache.
- `menubar/Sources/Pulse/UsageClient.swift` — `fetchUsageCached(cache, force)`.
- `menubar/Sources/Pulse/main.swift` — `refresh(force:)`; "Refresh Now" forces;
  `--selftest` rewritten to exercise the cache state machine.
- `CLAUDE.md`, `README.md` — documented the read-only + cache contract and the
  keychain-prompt expectations.

## Verification

- `npm test` — 47 pass.
- `cd tray-go && go test ./...` — pass; `go vet` clean.
- `cd menubar && swift build -c release && ./.build/release/Pulse --selftest` —
  all 22 checks pass.
- `grep` for write/refresh symbols in `menubar/Sources` — zero hits.
- Empirically confirmed on the affected machine that the attribute-only
  `security find-generic-password` read returns the `mdat` line without a prompt.

### Residual prompt budget

Because the app remains ad-hoc signed, "Always Allow" still cannot persist.
Expect roughly **one prompt per app launch/reboot plus one per Claude Code token
rotation** — never one per poll. Reaching zero prompts requires either
`CLAUDE_USAGE_TOKEN`, or Developer ID signing (which still cannot bypass Claude
Code's ACL on its own keychain item, so the cache work is needed regardless).

## One-time remediation for an already-broken machine

The existing keychain item may have been altered by the old write-back, and the
refresh-token family may already be revoked. Recover once:

1. Quit Pulse and remove it from Login Items temporarily.
2. Delete any Pulse-tainted keychain item — repeat until "could not be found":
   ```bash
   security delete-generic-password -s "Claude Code-credentials"
   ```
3. Re-login to Claude Code: run `claude`, then `/login`; confirm `/usage` works.
4. Install the rebuilt Pulse (`1.0.1`), re-add the login item, and launch.
   Expect exactly one keychain prompt — click **Allow**.
