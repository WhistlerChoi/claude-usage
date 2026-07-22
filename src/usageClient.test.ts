import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchUsage, AuthError } from "./usageClient";
import { CredentialCache, type CredentialSource } from "./credentialCache";

const okBody = {
  five_hour: { utilization: 42, resets_at: "2026-06-04T11:50:00+00:00" },
  seven_day: { utilization: 8, resets_at: null },
};

function makeCache(tokens: { fingerprint: string; secret: string }[]) {
  let i = 0;
  const source: CredentialSource = {
    async readFingerprint() {
      return tokens[Math.min(i, tokens.length - 1)].fingerprint;
    },
    async readSecret() {
      const t = tokens[Math.min(i, tokens.length - 1)].secret;
      i += 1;
      return t;
    },
  };
  return new CredentialCache(source, {});
}

function stubFetch(handler: (token: string) => { status: number; body?: unknown }) {
  const calls: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    const auth = (init?.headers as Record<string, string>)?.Authorization ?? "";
    const token = auth.replace("Bearer ", "");
    calls.push(token);
    const { status, body } = handler(token);
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => null },
      json: async () => body ?? {},
    };
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = original) };
}

test("401 with rotated credentials: invalidates, re-reads, retries exactly once", async () => {
  // After the first secret read the store advances to a new fingerprint+token
  const cache = makeCache([
    { fingerprint: "keychain:A", secret: "tok-old" },
    { fingerprint: "keychain:B", secret: "tok-new" },
  ]);
  const { calls, restore } = stubFetch((token) =>
    token === "tok-new" ? { status: 200, body: okBody } : { status: 401 }
  );
  try {
    const usage = await fetchUsage(false, cache);
    assert.equal(usage.fiveHour.utilization, 42);
    assert.deepEqual(calls, ["tok-old", "tok-new"]);
  } finally {
    restore();
  }
});

test("401 with unchanged credentials: throws AuthError, no infinite retry", async () => {
  const cache = makeCache([{ fingerprint: "keychain:A", secret: "tok-old" }]);
  const { calls, restore } = stubFetch(() => ({ status: 401 }));
  try {
    await assert.rejects(() => fetchUsage(false, cache), AuthError);
    assert.deepEqual(calls, ["tok-old"]);
    // next tick: cache is in rejected state, secret untouched, still auth error
    await assert.rejects(() => fetchUsage(false, cache));
    assert.deepEqual(calls, ["tok-old"]);
  } finally {
    restore();
  }
});

test("retried request that 401s again throws AuthError (no second retry)", async () => {
  const cache = makeCache([
    { fingerprint: "keychain:A", secret: "tok-old" },
    { fingerprint: "keychain:B", secret: "tok-new" },
  ]);
  const { calls, restore } = stubFetch(() => ({ status: 401 }));
  try {
    await assert.rejects(() => fetchUsage(false, cache), AuthError);
    assert.deepEqual(calls, ["tok-old", "tok-new"]);
  } finally {
    restore();
  }
});

test("403 is treated like 401", async () => {
  const cache = makeCache([{ fingerprint: "keychain:A", secret: "tok-old" }]);
  const { restore } = stubFetch(() => ({ status: 403 }));
  try {
    await assert.rejects(() => fetchUsage(false, cache), AuthError);
  } finally {
    restore();
  }
});
