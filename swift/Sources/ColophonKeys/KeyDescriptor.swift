import ColophonKit
import Foundation

/// A WebAuthn descriptor produced by the Rust registration parser; contains no private material.
public struct KeyDescriptor: Sendable, Equatable {
    /// Canonical protocol JSON the core parsed from the registration (0.4 form; kept for callers
    /// that still build 0.4 keyrings). For 0.5 use `view`.
    public let json: Data
    /// Uncompressed P-256 signing point.
    public let signing: Data
    /// Caller-selected relying party.
    public let relyingParty: String
    /// Credential lookup identifier; the core verifies signatures independently of this hint.
    public let credential: Data
    /// The origins this credential's authority ceremonies may come from (spec §3.1 `authorityOrigins`):
    /// 1 to 32, distinct, strictly ascending. Hosts that follow §18 set the authority-ceremony origin,
    /// the bare `rp` origin and the app's platform origin. Empty means the field is absent.
    public let authorityOrigins: [String]
    /// Other origins the credential may be used from (spec §3.1 `origins`), ascending. Usually empty.
    public let origins: [String]

    /// Parses COSE and registration authenticator data exclusively through the Rust core.
    public init(attestationObject: Data, relyingParty: String, authorityOrigins: [String] = [], origins: [String] = []) throws {
        let json = try parseRegistration(attestationObject: attestationObject, rp: relyingParty)
        struct Fields: Decodable { let signing: Data; let rp: String; let credential: Data }
        let fields = try JSONDecoder().decode(Fields.self, from: json)
        self.json = json
        signing = fields.signing
        self.relyingParty = fields.rp
        credential = fields.credential
        self.authorityOrigins = Set(authorityOrigins).sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        self.origins = Set(origins).sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
    }

    /// A WebAuthn descriptor as a verified history names it (the `KeyDescriptorView` a 0.5 export returns, for example
    /// `AdmittedHistory.ownerDescriptor`), so a device that did not register the passkey can use it. `json` is the
    /// registration parser's form of the same fields (`form`, `signing`, `rp`, `credential`, `origins` when present).
    /// A raw key, or a view without `rp` or `credential`, is `KeyProviderError.unsupportedHere`.
    public init(view: KeyDescriptorView) throws {
        guard view.form == .webauthn, let rp = view.rp, let credential = view.credential, view.signing.count == 65 else {
            throw KeyProviderError.unsupportedHere
        }
        var fields: [String: Any] = ["form": "webauthn", "signing": view.signing.base64EncodedString(), "rp": rp,
                                     "credential": credential.base64EncodedString()]
        if !view.origins.isEmpty { fields["origins"] = view.origins }
        json = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        signing = view.signing
        relyingParty = rp
        self.credential = credential
        authorityOrigins = view.authorityOrigins
        origins = view.origins
    }

    /// The descriptor in the protocol form every 0.5 export takes (`ControllerSpec.key`).
    public var view: KeyDescriptorView {
        KeyDescriptorView(form: .webauthn, signing: signing, agreement: nil, rp: relyingParty, credential: credential,
                          origins: origins, authorityOrigins: authorityOrigins)
    }
}
