import Foundation
import Security

enum CredentialsError: Error, LocalizedError {
    case notFound(String)
    case denied(String)
    var errorDescription: String? {
        switch self {
        case .notFound(let m): return m
        case .denied(let m): return m
        }
    }
}

private let keychainService = "Claude Code-credentials"

/// Extract accessToken from credentials JSON Data. { claudeAiOauth: { accessToken } } or { accessToken }.
func extractAccessToken(_ data: Data) -> String? {
    guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return nil
    }
    if let oauth = obj["claudeAiOauth"] as? [String: Any],
       let tok = oauth["accessToken"] as? String, !tok.isEmpty {
        return tok
    }
    if let tok = obj["accessToken"] as? String, !tok.isEmpty {
        return tok
    }
    return nil
}

private func credentialsFileURL() -> URL {
    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude/.credentials.json")
}

/// Read the credentials string from the macOS keychain. Returns nil if absent or denied.
/// This is the one read that can trigger a keychain ACL prompt.
private func readFromKeychain() -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecReturnData as String: true,
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
        return nil
    }
    return result as? Data
}

/// Read Claude Code's OAuth accessToken (the secret read — may prompt on macOS).
/// Prefers ~/.claude/.credentials.json; falls back to the macOS keychain.
/// Strictly read-only: Pulse never refreshes or writes Claude Code's credentials.
func readAccessToken() throws -> String {
    if let data = try? Data(contentsOf: credentialsFileURL()), let tok = extractAccessToken(data) {
        return tok
    }
    if let data = readFromKeychain(), let tok = extractAccessToken(data) {
        return tok
    }
    throw CredentialsError.notFound("Could not read credentials. Log in with Claude Code.")
}

// MARK: - Prompt-free change fingerprint

private func fileFingerprint() -> String? {
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: credentialsFileURL().path),
          let mtime = attrs[.modificationDate] as? Date else {
        return nil
    }
    return "file:\(mtime.timeIntervalSince1970)"
}

private func keychainFingerprint() -> String? {
    // kSecReturnAttributes without kSecReturnData: metadata only, never triggers an ACL prompt.
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecReturnAttributes as String: true,
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
          let attrs = result as? [String: Any],
          let mdat = attrs[kSecAttrModificationDate as String] as? Date else {
        return nil
    }
    return "keychain:\(mdat.timeIntervalSince1970)"
}

/// Prompt-free change fingerprint of the credential store: file mtime if the
/// credentials file exists, otherwise the keychain item's modification date.
/// nil means no credentials are present. The source prefix makes a
/// file<->keychain transition register as a change.
func readFingerprint() -> String? {
    fileFingerprint() ?? keychainFingerprint()
}
