import Foundation

/// The build's defaults (Info.plist, filled from build settings in `Config/TestApp.xcconfig`) and the person's settings,
/// kept as JSON in Application Support. Nothing here is secret: URLs, a slot name, the passkey's public registration.
struct BuildDefaults {
    /// The prefix a new account's home URL starts with; the slot is appended (`https://home.test/v1/libraries/`).
    let homePrefix: String
    /// Where requests for `homePrefix` are sent instead (`http://127.0.0.1:8790/v1/libraries/`); empty: sent as named.
    let reachPrefix: String
    /// The home service that provisions a slot for a new account and answers with the home's member request.
    let provisioner: String
    /// The WebAuthn relying party of the person's passkey (`id.toolsperson.com`).
    let relyingParty: String
    /// The staging home (`https://colophon.toolsperson.com/v1/libraries/`), reached directly, and its home service if any.
    let stagingPrefix: String
    let stagingProvisioner: String

    static let current: BuildDefaults = {
        let info = Bundle.main.infoDictionary ?? [:]
        func value(_ key: String, _ fallback: String) -> String {
            let text = (info[key] as? String)?.trimmingCharacters(in: .whitespaces) ?? ""
            return text.isEmpty || text.hasPrefix("$(") ? fallback : text
        }
        return BuildDefaults(homePrefix: value("ColophonHomePrefix", "https://home.test/v1/libraries/"),
                             reachPrefix: value("ColophonHomeReach", ""),
                             provisioner: value("ColophonProvisioner", ""),
                             relyingParty: value("ColophonRelyingParty", "id.toolsperson.com"),
                             stagingPrefix: value("ColophonStagingPrefix", "https://colophon.toolsperson.com/v1/libraries/"),
                             stagingProvisioner: value("ColophonStagingProvisioner", "https://colophon.toolsperson.com/v1/provision"))
    }()
}

enum OwnerChoice: String, Codable, Sendable {
    /// The person's passkey (ASAuthorization, PRF): a real owner.
    case passkey
    /// A software P-256 owner key in the Keychain. Debug and simulator builds only; for tests.
    case software
    /// This device joined an account: it holds a member key only and cannot approve, revoke or veto.
    case none
}

struct PasskeyRecord: Codable, Sendable, Equatable {
    /// The registration's attestation object (public: the credential's public key and ID).
    var attestationObject: Data
    var relyingParty: String
    var authorityOrigins: [String]
}

struct Settings: Codable, Sendable, Equatable {
    var homePrefix: String
    var reachPrefix: String
    var provisioner: String
    /// The token the local home service printed at start-up (it refuses requests without it).
    var provisionerToken = ""
    /// The account's slot at the home; set when this device creates or joins an account.
    var slot: String?
    var owner: OwnerChoice?
    var passkey: PasskeyRecord?
    /// Invites that failed to read or verify (the last hour counts; see `AppModel.attemptLimit`). Approving a device is
    /// bounded by the session's own pairing limiter (§7.3).
    var failures: [Date] = []

    init(defaults: BuildDefaults = .current) {
        homePrefix = defaults.homePrefix; reachPrefix = defaults.reachPrefix; provisioner = defaults.provisioner
    }

    private enum CodingKeys: String, CodingKey { case homePrefix, reachPrefix, provisioner, provisionerToken, slot, owner, passkey, failures }
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = BuildDefaults.current
        homePrefix = try c.decodeIfPresent(String.self, forKey: .homePrefix) ?? defaults.homePrefix
        reachPrefix = try c.decodeIfPresent(String.self, forKey: .reachPrefix) ?? defaults.reachPrefix
        provisioner = try c.decodeIfPresent(String.self, forKey: .provisioner) ?? defaults.provisioner
        provisionerToken = try c.decodeIfPresent(String.self, forKey: .provisionerToken) ?? ""
        slot = try c.decodeIfPresent(String.self, forKey: .slot)
        owner = try c.decodeIfPresent(OwnerChoice.self, forKey: .owner)
        passkey = try c.decodeIfPresent(PasskeyRecord.self, forKey: .passkey)
        failures = try c.decodeIfPresent([Date].self, forKey: .failures) ?? []
    }

    /// The home's base URL as the account names it (no trailing slash).
    var homeBase: String? {
        guard let slot else { return nil }
        return (homePrefix.hasSuffix("/") ? homePrefix : homePrefix + "/") + slot
    }

    static func newSlot() -> String {
        "t" + (0..<5).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }
}

/// Where this app keeps things. One account per install.
enum Paths {
    static var root: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("ColophonTest", isDirectory: true)
    }
    static var settings: URL { root.appendingPathComponent("settings.json") }
    static var account: URL { root.appendingPathComponent("account", isDirectory: true) }
    static var records: URL { account.appendingPathComponent("records", isDirectory: true) }
    static var session: URL { account.appendingPathComponent("session", isDirectory: true) }
    /// Debug builds write the last pairing payload they showed here, for scripted runs (public bytes only).
    static var outbox: URL { FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("outbox.txt") }

    static func loadSettings() -> Settings {
        guard let data = try? Data(contentsOf: settings), let decoded = try? JSONDecoder().decode(Settings.self, from: data) else { return Settings() }
        return decoded
    }
    static func save(_ value: Settings) throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try JSONEncoder().encode(value).write(to: settings, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
