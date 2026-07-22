import { CredentialsError, readAccessToken, readFingerprint } from "./credentials";

/**
 * Injectable credential source. readFingerprint must never trigger a keychain
 * ACL prompt (metadata only); readSecret is the one call that may prompt.
 */
export interface CredentialSource {
  readFingerprint(): Promise<string | null>;
  readSecret(): Promise<string>;
}

const LOGIN_MESSAGE = "Could not read credentials. Log in with Claude Code.";
const DENIED_MESSAGE = "Keychain access denied. Use Refresh Now to try again.";
const EXPIRED_MESSAGE = "Authentication expired. Log in again.";

/**
 * Caches the access token so the secret store (macOS keychain / credentials
 * file) is read at most once per change. Every getToken() call does a
 * prompt-free fingerprint read; the secret is re-read only when the
 * fingerprint changes, so keychain ACL prompts are capped at roughly one per
 * Claude Code token rotation instead of one per poll.
 */
export class CredentialCache {
  private token: string | undefined;
  private fingerprint: string | null | undefined;
  private rejectedFingerprint: string | null | undefined;
  private rejectionMessage = EXPIRED_MESSAGE;

  constructor(
    private readonly source: CredentialSource = {
      readFingerprint,
      readSecret: readAccessToken,
    },
    private readonly env: NodeJS.ProcessEnv = process.env
  ) {}

  /**
   * Return the current access token.
   * force bypasses only a previous rejection (explicit user retry may
   * prompt once); a healthy cached token is returned without any secret read.
   */
  async getToken(force = false): Promise<string> {
    const envToken = this.env.CLAUDE_USAGE_TOKEN;
    if (envToken) {
      return envToken;
    }

    const fp = await this.source.readFingerprint();

    if (this.token !== undefined && fp === this.fingerprint) {
      return this.token;
    }

    if (fp === null) {
      this.token = undefined;
      this.fingerprint = null;
      throw new CredentialsError(LOGIN_MESSAGE);
    }

    if (!force && this.rejectedFingerprint !== undefined && fp === this.rejectedFingerprint) {
      throw new CredentialsError(this.rejectionMessage);
    }

    try {
      const token = await this.source.readSecret();
      this.token = token;
      this.fingerprint = fp;
      this.rejectedFingerprint = undefined;
      return token;
    } catch {
      this.token = undefined;
      this.rejectedFingerprint = fp;
      this.rejectionMessage = DENIED_MESSAGE;
      throw new CredentialsError(DENIED_MESSAGE);
    }
  }

  /** Call on HTTP 401/403: the cached token was rejected by the API. */
  invalidate(): void {
    this.token = undefined;
    this.rejectedFingerprint = this.fingerprint;
    this.rejectionMessage = EXPIRED_MESSAGE;
  }
}

export const defaultCache = new CredentialCache();
