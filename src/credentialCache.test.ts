import { test } from "node:test";
import assert from "node:assert/strict";
import { CredentialCache, type CredentialSource } from "./credentialCache";
import { CredentialsError, extractKeychainMdat } from "./credentials";

/** Fake source with call counters and mutable state. */
function fakeSource(initial: { fingerprint: string | null; secret?: string | Error }) {
  const state = {
    fingerprint: initial.fingerprint,
    secret: initial.secret ?? "tok-1",
    fingerprintReads: 0,
    secretReads: 0,
  };
  const source: CredentialSource = {
    async readFingerprint() {
      state.fingerprintReads += 1;
      return state.fingerprint;
    },
    async readSecret() {
      state.secretReads += 1;
      if (state.secret instanceof Error) {
        throw state.secret;
      }
      return state.secret;
    },
  };
  return { source, state };
}

test("steady state: unchanged fingerprint reads secret exactly once", async () => {
  const { source, state } = fakeSource({ fingerprint: "keychain:A", secret: "tok-1" });
  const cache = new CredentialCache(source, {});
  assert.equal(await cache.getToken(), "tok-1");
  assert.equal(await cache.getToken(), "tok-1");
  assert.equal(await cache.getToken(), "tok-1");
  assert.equal(state.secretReads, 1);
  assert.equal(state.fingerprintReads, 3);
});

test("fingerprint change triggers exactly one re-read", async () => {
  const { source, state } = fakeSource({ fingerprint: "keychain:A", secret: "tok-1" });
  const cache = new CredentialCache(source, {});
  assert.equal(await cache.getToken(), "tok-1");
  state.fingerprint = "keychain:B";
  state.secret = "tok-2";
  assert.equal(await cache.getToken(), "tok-2");
  assert.equal(await cache.getToken(), "tok-2");
  assert.equal(state.secretReads, 2);
});

test("invalidate + unchanged fingerprint: throws without touching the secret", async () => {
  const { source, state } = fakeSource({ fingerprint: "keychain:A", secret: "tok-1" });
  const cache = new CredentialCache(source, {});
  await cache.getToken();
  cache.invalidate();
  await assert.rejects(() => cache.getToken(), (err: unknown) => {
    assert.ok(err instanceof CredentialsError);
    assert.match((err as Error).message, /Authentication expired/);
    return true;
  });
  await assert.rejects(() => cache.getToken());
  assert.equal(state.secretReads, 1);
});

test("invalidate + changed fingerprint: re-reads the secret", async () => {
  const { source, state } = fakeSource({ fingerprint: "keychain:A", secret: "tok-1" });
  const cache = new CredentialCache(source, {});
  await cache.getToken();
  cache.invalidate();
  state.fingerprint = "keychain:B";
  state.secret = "tok-2";
  assert.equal(await cache.getToken(), "tok-2");
  assert.equal(state.secretReads, 2);
});

test("denied read: no further secret reads until force or fingerprint change", async () => {
  const { source, state } = fakeSource({
    fingerprint: "keychain:A",
    secret: new CredentialsError("Could not read credentials. Log in with Claude Code."),
  });
  const cache = new CredentialCache(source, {});
  await assert.rejects(() => cache.getToken(), (err: unknown) => {
    assert.match((err as Error).message, /Keychain access denied\. Use Refresh Now to try again\./);
    return true;
  });
  await assert.rejects(() => cache.getToken());
  await assert.rejects(() => cache.getToken());
  assert.equal(state.secretReads, 1);
  // force retries once (explicit user intent)
  state.secret = "tok-1";
  assert.equal(await cache.getToken(true), "tok-1");
  assert.equal(state.secretReads, 2);
});

test("null fingerprint: login message with zero secret reads; auto-recovers when creds appear", async () => {
  const { source, state } = fakeSource({ fingerprint: null, secret: "tok-1" });
  const cache = new CredentialCache(source, {});
  await assert.rejects(() => cache.getToken(), (err: unknown) => {
    assert.ok(err instanceof CredentialsError);
    assert.match((err as Error).message, /Could not read credentials\. Log in with Claude Code\./);
    return true;
  });
  assert.equal(state.secretReads, 0);
  state.fingerprint = "keychain:A";
  assert.equal(await cache.getToken(), "tok-1");
  assert.equal(state.secretReads, 1);
});

test("file-to-keychain source transition counts as a change", async () => {
  const { source, state } = fakeSource({ fingerprint: "file:1000", secret: "tok-file" });
  const cache = new CredentialCache(source, {});
  assert.equal(await cache.getToken(), "tok-file");
  state.fingerprint = "keychain:1000";
  state.secret = "tok-keychain";
  assert.equal(await cache.getToken(), "tok-keychain");
  assert.equal(state.secretReads, 2);
});

test("CLAUDE_USAGE_TOKEN env override bypasses the source entirely", async () => {
  const { source, state } = fakeSource({ fingerprint: "keychain:A" });
  const cache = new CredentialCache(source, { CLAUDE_USAGE_TOKEN: "tok-env" });
  assert.equal(await cache.getToken(), "tok-env");
  assert.equal(state.fingerprintReads, 0);
  assert.equal(state.secretReads, 0);
});

test("force does not bypass a healthy cache (Refresh Now stays prompt-free)", async () => {
  const { source, state } = fakeSource({ fingerprint: "keychain:A", secret: "tok-1" });
  const cache = new CredentialCache(source, {});
  assert.equal(await cache.getToken(), "tok-1");
  assert.equal(await cache.getToken(true), "tok-1");
  assert.equal(state.secretReads, 1);
});

// Verbatim `security find-generic-password -s "Claude Code-credentials"` output (no -w)
const realCliOutput = `keychain: "/Users/whistler/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="Claude Code-credentials"
    "acct"<blob>="whistler"
    "cdat"<timedate>=0x32303236303732323031323533305A00  "20260722012530Z\\000"
    "mdat"<timedate>=0x32303236303732323031323535375A00  "20260722012557Z\\000"
    "svce"<blob>="Claude Code-credentials"
`;

test("extractKeychainMdat captures the raw mdat line from real CLI output", () => {
  const mdat = extractKeychainMdat(realCliOutput);
  assert.ok(mdat);
  assert.ok(mdat.includes("0x32303236303732323031323535375A00"));
  assert.ok(mdat.includes("20260722012557Z"));
});

test("extractKeychainMdat returns null when absent", () => {
  assert.equal(extractKeychainMdat("keychain: whatever\nno attributes here\n"), null);
});
