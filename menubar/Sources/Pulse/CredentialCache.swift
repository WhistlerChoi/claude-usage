import Foundation

/// Caches the access token so the secret store (macOS keychain / credentials
/// file) is read at most once per change. Every getToken() call does a
/// prompt-free fingerprint read; the secret is re-read only when the
/// fingerprint changes, so keychain ACL prompts are capped at roughly one per
/// Claude Code token rotation instead of one per poll.
final class CredentialCache {
    private let envToken: () -> String?
    private let readFingerprintFn: () -> String?
    private let readSecretFn: () throws -> String

    private var token: String?
    private var fingerprint: String?
    private var rejectedFingerprint: String?
    private var hasRejected = false
    private var rejectionError: Error = UsageError.auth

    init(
        envToken: @escaping () -> String? = { ProcessInfo.processInfo.environment["CLAUDE_USAGE_TOKEN"] },
        readFingerprintFn: @escaping () -> String? = readFingerprint,
        readSecretFn: @escaping () throws -> String = readAccessToken
    ) {
        self.envToken = envToken
        self.readFingerprintFn = readFingerprintFn
        self.readSecretFn = readSecretFn
    }

    /// Return the current access token.
    /// force bypasses only a previous rejection (an explicit user retry may
    /// prompt once); a healthy cached token is returned without any secret read.
    func getToken(force: Bool = false) throws -> String {
        if let env = envToken(), !env.isEmpty {
            return env
        }

        let fp = readFingerprintFn()

        if let token, fp == fingerprint {
            return token
        }

        guard let fp else {
            token = nil
            fingerprint = nil
            throw CredentialsError.notFound("Could not read credentials. Log in with Claude Code.")
        }

        if !force, hasRejected, fp == rejectedFingerprint {
            throw rejectionError
        }

        do {
            let secret = try readSecretFn()
            token = secret
            fingerprint = fp
            hasRejected = false
            return secret
        } catch {
            token = nil
            rejectedFingerprint = fp
            hasRejected = true
            let denied = CredentialsError.denied("Keychain access denied. Use Refresh Now to try again.")
            rejectionError = denied
            throw denied
        }
    }

    /// Call on HTTP 401/403: the cached token was rejected by the API.
    func invalidate() {
        token = nil
        rejectedFingerprint = fingerprint
        hasRejected = true
        rejectionError = UsageError.auth
    }
}
