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

    /// The passkey of a controller a joining device read from the history it accepted
    /// (`AdmittedHistory.ownerDescriptor(keyID:)`), so a device that did not register the passkey can use it. `json` is
    /// the registration parser's form of the same fields (`form`, `signing`, `rp`, `credential`, `origins` when present).
    public init(passkey: OwnerPasskey) throws {
        let view = passkey.view
        guard let rp = view.rp, let credential = view.credential else { throw KeyProviderError.unsupportedHere }
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

    /// A stable serialization for this device's own storage: `json`'s fields plus `authorityOrigins`, keys sorted.
    /// `init(stored:)` reads it back.
    public var stored: Data {
        get throws {
            var fields: [String: Any] = ["form": "webauthn", "signing": signing.base64EncodedString(), "rp": relyingParty,
                                         "credential": credential.base64EncodedString()]
            if !origins.isEmpty { fields["origins"] = origins }
            if !authorityOrigins.isEmpty { fields["authorityOrigins"] = authorityOrigins }
            return try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        }
    }

    /// Restores a descriptor from `stored`, at every launch of a device that joined as a passkey owner. Only for a
    /// descriptor this device stored after an accepted join (`init(passkey:)`); never for data received from elsewhere.
    /// The authority verifier still checks every signature the key makes.
    public init(stored: Data) throws {
        struct Fields: Decodable {
            let form: String; let signing: Data; let rp: String; let credential: Data
            let origins: [String]?; let authorityOrigins: [String]?
        }
        let f = try JSONDecoder().decode(Fields.self, from: stored)
        guard f.form == "webauthn", f.signing.count == 65 else { throw KeyProviderError.unsupportedHere }
        var fields: [String: Any] = ["form": "webauthn", "signing": f.signing.base64EncodedString(), "rp": f.rp,
                                     "credential": f.credential.base64EncodedString()]
        if let o = f.origins, !o.isEmpty { fields["origins"] = o }
        json = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        signing = f.signing
        relyingParty = f.rp
        credential = f.credential
        origins = f.origins ?? []
        authorityOrigins = f.authorityOrigins ?? []
    }

    /// The descriptor in the protocol form every 0.5 export takes (`ControllerSpec.key`).
    public var view: KeyDescriptorView {
        KeyDescriptorView(form: .webauthn, signing: signing, agreement: nil, rp: relyingParty, credential: credential,
                          origins: origins, authorityOrigins: authorityOrigins)
    }
}
