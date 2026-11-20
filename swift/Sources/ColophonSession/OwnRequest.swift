import Foundation

/// This device's own membership request (spec §9.1), one code path the session and anything that asks for it before the session opens share: the terms are
/// the configuration's (namespaces, access, services), the label and kind its member's, `created` a second before
/// `nowMs`. It is stored once at `requests/<member ID>.json` and reused from there, so a session opened after a join
/// finds the very request the owner approved.
enum OwnRequest {
    static func path(_ memberID: String) -> String { "requests/\(memberID).json" }

    static func make(_ configuration: SessionConfiguration, keys: any AsyncKeyProvider, account: String, nowMs: Int64) async throws -> Data {
        let publicKeys = try await keys.publicKeys()
        let spec = RequestSpec(account: account, signing: publicKeys.signing, agreement: publicKeys.agreement, label: configuration.memberLabel,
            kind: SessionWorker.accountKind(configuration.memberKind),
            termsJson: SessionWorker.terms(namespaces: configuration.namespaces, access: configuration.access, expires: nil, budget: nil, services: configuration.services),
            created: try accountFormatDate(ms: nowMs - 1000), custody: nil, operator: nil, endpoints: [])
        let request = try AccountRequest.prepare(spec: spec)
        let signature = try await keys.sign(body: try request.step().body)
        return try request.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil)).raw
    }

    /// The stored request of `memberID`, or a new one made and stored.
    static func ensure(_ configuration: SessionConfiguration, medium: any RecordMedium, keys: any AsyncKeyProvider, account: String,
                       memberID: String, nowMs: Int64) async throws -> Data {
        let path = path(memberID)
        if let stored = try? medium.read(path) { return stored }
        let bytes = try await make(configuration, keys: keys, account: account, nowMs: nowMs)
        try medium.write([MediumWrite(path: path, bytes: bytes)])
        return bytes
    }

    /// The account a request envelope names (its body's `account`), or nil when it does not parse.
    static func account(_ raw: Data) -> String? {
        guard let envelope = try? JSONSerialization.jsonObject(with: raw) as? [String: Any], let text = envelope["body"] as? String,
              let body = Data(base64Encoded: text), let value = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return nil }
        return value["account"] as? String
    }
}
