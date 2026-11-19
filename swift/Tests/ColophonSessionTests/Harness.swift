import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
import ColophonSession

/// One device of a test account: a session over a shared medium, with software keys.
@MainActor final class Device {
    let home: URL
    let medium: MemoryMedium
    let member: SoftwareKeys
    let owner: SoftwareKeys
    let session: ColophonSession
    let secrets: MemoryDeviceSecrets
    private let makeSession: @MainActor () -> ColophonSession
    init(medium: MemoryMedium = MemoryMedium(), member: SoftwareKeys = SoftwareKeys(), owner: SoftwareKeys = SoftwareKeys(),
         homes: [HomeConfiguration] = [], createWithoutHome: Bool = true, recovery: SoftwareKeys? = nil, additional: [AdditionalController] = [], namespaces: [String] = ["reading.saved"], services: [ServiceTerms] = [], libraryNamespaces: [String]? = nil,
         history: HistoryAccess? = nil, headQuorum: Int? = nil, keys: (any AsyncKeyProvider)? = nil, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.medium = medium; self.member = member; self.owner = owner
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString), secrets = MemoryDeviceSecrets()
        self.home = home; self.secrets = secrets
        makeSession = {
            ColophonSession(configuration: .init(memberLabel: "Test device", namespaces: namespaces, services: services, libraryNamespaces: libraryNamespaces, location: .memory(medium),
                privateContainer: home, keys: keys ?? member, ownerController: owner, recoveryKeys: recovery, homes: homes, createWithoutHome: createWithoutHome, additionalControllers: additional,
                deviceSecrets: secrets, history: history, headQuorum: headQuorum, now: clock))
        }
        session = makeSession()
    }
    /// Another session over this device's medium, private container and device secrets: a relaunch.
    func relaunch() -> ColophonSession { makeSession() }
    isolated deinit { try? FileManager.default.removeItem(at: home) }
}

// MARK: Pairing before approval (§7.3, §9.1)

/// The six-digit code between a joining device and an approving one, each through its own session, with the messages
/// passed between them as an app would carry them: the request with the commitment, the nonce, the reveal. Both screens' digits are
/// compared and both devices confirm. Returns the request the approving device sees and its confirmed pairing.
@MainActor func pairByCode(joining: ColophonSession, approving: ColophonSession) async throws -> (AccessRequest, AccountPairing) {
    let raw = try await joining.exportRequest()
    let j = try await joining.beginJoinPairing()
    let start = try await approving.beginApproval(commitment: try j.commitment())
    let reveal = try #require(try j.receiveNonce(na: start.nonce))
    let code = try await approving.approvalCode(pairing: start.pairing, e: reveal.e, nb: reveal.nb)
    #expect(code == (try j.digits()), "both screens show the same six digits")
    #expect(code.count == 6 && code.allSatisfy(\.isNumber))
    try j.confirm(); try start.pairing.confirm()
    let info = try accountRequestInfo(raw: raw)
    return (AccessRequest(id: info.member, label: info.label, kind: info.kind, termsJSON: info.termsJson, record: info.raw), start.pairing)
}

/// Pairs by the code and approves.
@MainActor func approveByCode(joining: ColophonSession, approving: ColophonSession, grant: GrantOptions? = nil) async throws {
    let (request, pairing) = try await pairByCode(joining: joining, approving: approving)
    try await approving.approve(request, pairing: pairing, grant: grant)
}

/// The scan path: the approving device scans the joining device's request (its canonical envelope) and approves it.
@MainActor func approveByScan(joining: ColophonSession, approving: ColophonSession, grant: GrantOptions? = nil) async throws {
    let scanned = try await approving.scanRequest(try await joining.exportRequest())
    try await approving.approve(scanned.request, pairing: scanned.pairing, grant: grant)
}
