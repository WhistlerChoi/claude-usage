import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const execFileAsync = promisify(execFile);

const KEYCHAIN_SERVICE = "Claude Code-credentials";

export class CredentialsError extends Error {}

/** Extract accessToken from a credentials JSON string. Format: { claudeAiOauth: { accessToken } } or { accessToken }. */
export function extractAccessToken(raw: string): string {
  let token: unknown;
  try {
    const parsed = JSON.parse(raw.trim());
    token = parsed?.claudeAiOauth?.accessToken ?? parsed?.accessToken;
  } catch {
    throw new CredentialsError("Could not read credentials. Log in with Claude Code.");
  }
  if (typeof token !== "string" || token.length === 0) {
    throw new CredentialsError("Could not find accessToken. You may need to log in again.");
  }
  return token;
}

function credentialsFilePath(): string {
  return join(homedir(), ".claude", ".credentials.json");
}

/** Read credentials from the common file path (Windows/Linux/macOS). Returns null if absent. */
async function readFromFile(): Promise<string | null> {
  try {
    return await readFile(credentialsFilePath(), "utf8");
  } catch {
    return null;
  }
}

/** Read credentials from the macOS keychain. Returns null if absent. */
async function readFromKeychain(): Promise<string | null> {
  if (process.platform !== "darwin") {
    return null;
  }
  try {
    const { stdout } = await execFileAsync("security", [
      "find-generic-password",
      "-s",
      KEYCHAIN_SERVICE,
      "-w",
    ]);
    return stdout;
  } catch {
    return null;
  }
}

/** Capture the raw "mdat" (modification date) line from `security find-generic-password` attribute output. */
export function extractKeychainMdat(output: string): string | null {
  const match = output.match(/"mdat"<timedate>=(.+)/);
  return match ? match[1].trim() : null;
}

async function readFileFingerprint(): Promise<string | null> {
  try {
    const s = await stat(credentialsFilePath());
    return `file:${s.mtimeMs}`;
  } catch {
    return null;
  }
}

async function readKeychainFingerprint(): Promise<string | null> {
  if (process.platform !== "darwin") {
    return null;
  }
  try {
    // No -w: attribute-only read, never triggers a keychain ACL prompt.
    const { stdout } = await execFileAsync("security", [
      "find-generic-password",
      "-s",
      KEYCHAIN_SERVICE,
    ]);
    const mdat = extractKeychainMdat(stdout);
    return mdat ? `keychain:${mdat}` : null;
  } catch {
    return null;
  }
}

/**
 * Prompt-free change fingerprint of the credential store: file mtime if the
 * credentials file exists, otherwise the keychain item's mdat attribute.
 * null means no credentials are present. The source prefix makes a
 * file<->keychain transition register as a change.
 */
export async function readFingerprint(): Promise<string | null> {
  return (await readFileFingerprint()) ?? (await readKeychainFingerprint());
}

/**
 * Read Claude Code's OAuth accessToken (the secret read — may prompt on macOS).
 * - First ~/.claude/.credentials.json (default on Windows/Linux, and used on macOS if present)
 * - Otherwise the macOS keychain
 */
export async function readAccessToken(): Promise<string> {
  const fileRaw = await readFromFile();
  if (fileRaw) {
    return extractAccessToken(fileRaw);
  }

  const keychainRaw = await readFromKeychain();
  if (keychainRaw) {
    return extractAccessToken(keychainRaw);
  }

  throw new CredentialsError(
    "Could not read credentials. Log in with Claude Code."
  );
}
