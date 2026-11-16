import ColophonKeys
import ColophonSession
import Foundation
import Observation
import Security

/// One line of the event log. Phases, sync outcomes, errors, key IDs and URLs only: never a secret.
struct LogEntry: Identifiable, Sendable {
    let id = UUID()
    let at: Date
    let text: String
}

/// The outcome of one sync the app asked for, as the status screen shows it. `complete` only when the pass succeeded
/// and no home fault or issue is left; a pass that ran but left faults is `incomplete`, never success.
struct SyncOutcome: Sendable {
    enum Kind: String, Sendable { case complete, incomplete, failed }
    let at: Date
    let kind: Kind
    let detail: String
}

@Observable @MainActor final class AppModel {
    static let service = "works.luff.colophon.testapp"
    static let deviceKeyService = "works.luff.colophon.testapp.device-key"
    private static let logQueue = DispatchQueue(label: "works.luff.colophon.testapp.log")

    private(set) var settings = Paths.loadSettings()
    private(set) var session: ColophonSession?
    let observer = HomeObserver()
    private(set) var log: [LogEntry] = []
    private(set) var notes: [Note] = []
    private(set) var notesProblem: String?
    private(set) var heldAndRefused = (held: 0, refused: 0)
    private(set) var lastSync: SyncOutcome?
    private(set) var busy: String?
    /// The last action's error, in full.
    var actionError: String?
    /// The last pairing payload this device showed (an invite or its request).
    private(set) var shownPayload: String?
    let presentation = WebAuthnPresentationContext()

    var isOwner: Bool { settings.owner == .passkey || settings.owner == .software }
    var hasAccount: Bool { settings.slot != nil && session != nil }

    init() {
        #if DEBUG
        // UI tests start from a fresh install's state, and may hand the app a link at launch (a link opened from outside
        // asks "Open in…?" first, which a scripted run cannot answer).
        let link = ProcessInfo.processInfo.environment["COLOPHON_OPEN_URL"].flatMap(URL.init(string:))
        if CommandLine.arguments.contains("-uiTestReset") {
            settings = Settings()
            let token = ProcessInfo.processInfo.environment["COLOPHON_PROVISIONER_TOKEN"]
            Task {
                await resetDevice()
                if let token { settings.provisionerToken = token; try? Paths.save(settings) }
                if let link { await open(link) }
            }
            return
        }
        if let link { Task { await open(link) } }
        #endif
        if settings.slot != nil { openSession(request: nil) }
        record("app started; home prefix \(settings.homePrefix), reach \(settings.reachPrefix.isEmpty ? "-" : settings.reachPrefix)")
    }

    // MARK: Log

    func record(_ text: String) {
        log.append(LogEntry(at: .now, text: text))
        if log.count > 200 { log.removeFirst(log.count - 200) }
        #if DEBUG
        // Debug builds mirror the log to Documents/log.txt for scripted runs (the same non-secret lines).
        let line = Data("\(Date.now.formatted(.iso8601)) \(text)\n".utf8)
        let url = Paths.outbox.deletingLastPathComponent().appendingPathComponent("log.txt")
        Self.logQueue.async {
            if let handle = try? FileHandle(forWritingTo: url) { _ = try? handle.seekToEnd(); try? handle.write(contentsOf: line); try? handle.close() }
            else { try? line.write(to: url) }
        }
        #endif
    }

    private var seen: (phase: String, error: String?, sync: String, faults: Int, issues: Int, pending: Int, members: Int, requests: Int)?
    /// Logs what changed in the session each time an observed property changes.
    private func track() {
        guard let session else { return }
        withObservationTracking {
            _ = (session.phase, session.lastError, session.syncState, session.homeFaults, session.homeIssues,
                 session.notices, session.members, session.requests)
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in self?.logChanges(); self?.track() }
        }
    }
    private func logChanges() {
        guard let session else { return }
        let now = ("\(session.phase)", session.lastError, "\(session.syncState)", session.homeFaults.count, session.homeIssues.count,
                   session.notices.pending.count, session.members.count, session.requests.count)
        let before = seen
        seen = now
        if before?.phase != now.0 { record("phase \(now.0)") }
        if before?.error != now.1, let error = now.1 { record("session error: \(error)") }
        if before?.sync != now.2 { record("sync state \(now.2)") }
        if before?.faults != now.3 { record("home faults: \(session.homeFaults.map(Self.describe).joined(separator: "; ").ifEmpty("none"))") }
        if before?.issues != now.4 { record("home issues: \(session.homeIssues.map { "\($0.problem)" }.joined(separator: "; ").ifEmpty("none"))") }
        if before?.pending != now.5 { record("pending changes: \(now.5)") }
        if before?.members != now.6 { record("members: \(now.6)") }
        if before?.requests != now.7 { record("requests waiting: \(now.7)") }
    }
    static func describe(_ fault: HomeFault) -> String {
        let f = fault.fault
        return "\(f.kind)" + (f.status.map { " \($0)" } ?? "") + (f.code.map { " \($0)" } ?? "") + (f.why.map { " (\($0))" } ?? "")
    }

    // MARK: Session

    private var memberKeys: KeychainKeys {
        #if targetEnvironment(simulator)
        KeychainKeys(service: Self.service, account: "member", backend: .software)
        #else
        KeychainKeys(service: Self.service, account: "member", backend: .secureEnclave)
        #endif
    }

    private func ownerKeys() -> any AsyncKeyProvider {
        switch settings.owner {
        case .passkey:
            if let record = settings.passkey,
               let descriptor = try? KeyDescriptor(attestationObject: record.attestationObject, relyingParty: record.relyingParty,
                                                   authorityOrigins: record.authorityOrigins) {
                return PasskeyProvider(descriptor: descriptor)
            }
            return NoOwner()
        case .software:
            #if DEBUG || targetEnvironment(simulator)
            return KeychainKeys(service: Self.service, account: "owner", backend: .software)
            #else
            return NoOwner()
            #endif
        case .some(.none), nil:
            return NoOwner()
        }
    }

    /// Builds the one session for this install's account. `request` is set only when this device creates the account.
    private func openSession(request: (@Sendable (String) async throws -> Data)?) {
        guard let base = settings.homeBase, let endpoint = URL(string: base + "/") else { return }
        let transport = MappedTransport(homePrefix: settings.homePrefix, reachPrefix: settings.reachPrefix, observer: observer)
        let home = HomeConfiguration(endpoint: endpoint, label: "Test home", request: request, transport: transport)
        try? FileManager.default.createDirectory(at: Paths.records, withIntermediateDirectories: true)
        try? FileManager.default.createDirectory(at: Paths.session, withIntermediateDirectories: true)
        let configuration = SessionConfiguration(
            memberLabel: "iPhone test app", memberKind: .app, namespaces: [NotesFold.namespace],
            location: .folder(Paths.records), privateContainer: Paths.session,
            keys: memberKeys, ownerController: ownerKeys(), homes: [home],
            deviceSecrets: KeychainDeviceSecrets(service: Self.deviceKeyService))
        let session = ColophonSession(configuration: configuration)
        self.session = session
        track()
        Task { await session.restore(); logChanges() }
    }

    private func perform(_ label: String, _ body: () async throws -> Void) async {
        busy = label; actionError = nil
        defer { busy = nil }
        do { try await body() } catch {
            actionError = "\(label) failed: \(Self.message(error))"
            record(actionError ?? "")
        }
    }
    static func message(_ error: Error) -> String {
        if let colophon = error as? ColophonError { return "\(colophon)" }
        let localized = (error as? LocalizedError)?.errorDescription
        return localized.map { "\($0) [\(error)]" } ?? "\(error)"
    }

    func updateHome(prefix: String, reach: String, provisioner: String, token: String) {
        guard settings.slot == nil else { return }
        settings.provisionerToken = token.trimmingCharacters(in: .whitespaces)
        settings.homePrefix = prefix.trimmingCharacters(in: .whitespaces)
        settings.reachPrefix = reach.trimmingCharacters(in: .whitespaces)
        settings.provisioner = provisioner.trimmingCharacters(in: .whitespaces)
        try? Paths.save(settings)
    }

    // MARK: Create and join

    func create(owner: OwnerChoice) async {
        await perform("Create account") {
            guard !settings.provisioner.isEmpty else { throw Provisioner.Failure(text: "Set the home service URL first: it provisions the home for the new account.") }
            var next = settings
            next.slot = Settings.newSlot()
            next.owner = owner
            if owner == .passkey { next.passkey = try await registerPasskey() }
            guard let base = next.homeBase else { return }
            let service = next.provisioner, token = next.provisionerToken, slot = next.slot ?? ""
            settings = next
            try Paths.save(settings)
            record("creating an account at \(base) (owner: \(owner.rawValue))")
            openSession(request: { account in
                try await Provisioner.memberRequest(service: service, token: token, slot: slot, base: base, account: account)
            })
            guard let session else { return }
            if owner == .passkey {
                try await presentation.perform { await session.create() }
            } else {
                await session.create()
            }
            if session.phase != .ready {
                throw Provisioner.Failure(text: "the account was not created: phase \(session.phase), \(session.lastError ?? "no error given")")
            }
            record("account \(session.libraryID ?? "-") created; this device's member \(session.memberID ?? "-")")
        }
    }

    /// Registers a passkey for the relying party (ASAuthorization). The attestation object is public and kept so the
    /// descriptor can be rebuilt each launch.
    private func registerPasskey() async throws -> PasskeyRecord {
        let rp = BuildDefaults.current.relyingParty
        let origins = ["https://\(rp)"]
        let recorder = RecordingCeremonies()
        let challenge = try SecretBytes.random(count: 32).withUnsafeBytes { Data($0) }
        let userID = try PasskeyProvider.userID(account: nil)
        _ = try await presentation.perform {
            try await PasskeyProvider.register(relyingParty: rp, userID: userID, userName: "Colophon test", challenge: challenge,
                                               authorityOrigins: origins, ceremonies: recorder)
        }
        guard let attestation = recorder.attestation else { throw KeyProviderError.credentialMissing }
        return PasskeyRecord(attestationObject: attestation, relyingParty: rp, authorityOrigins: origins)
    }

    /// An invite that a link, a scan or a paste brought, waiting for the person to confirm it. Nothing is stored and no
    /// request is sent until they do.
    struct PendingInvite: Equatable {
        let text: String
        let invite: PairingPayload.Invite
        /// The home's host, and the account ID in short form, as the confirmation screen shows them.
        var host: String { URL(string: invite.homePrefix)?.host ?? invite.homePrefix }
        var accountShort: String { String(invite.account.prefix(8)) + "…" + String(invite.account.suffix(4)) }
    }
    private(set) var pendingInvite: PendingInvite?
    /// A request a link brought, shown in Devices for the person to import or ignore; never imported by the link.
    var pendingRequestText: String?
    /// Requests whose code the person said matches on both screens, this run only.
    private(set) var confirmedCodes: Set<String> = []

    /// Decodes an invite (bounded) and shows it for confirmation. Stores nothing.
    func prepareJoin(_ text: String) async {
        await perform("Read invite") {
            try checkAttempts()
            do {
                let invite = try PairingPayload.decodeInvite(text)
                pendingInvite = PendingInvite(text: text, invite: invite)
                record("invite read: home \(pendingInvite?.host ?? "-"), account \(pendingInvite?.accountShort ?? "-"); waiting for confirmation")
            } catch { countFailure(); throw error }
        }
    }
    func cancelJoin() { pendingInvite = nil; record("invite dismissed") }

    /// The person confirmed: verify the invite's history in memory first, and only when it verifies and names the account
    /// the invite claims, store it and the settings, open the session and show this device's request.
    func confirmJoin() async {
        guard let pending = pendingInvite else { return }
        await perform("Join account") {
            try checkAttempts()
            let invite = pending.invite
            let files = invite.history
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let verified = try await Task.detached { () throws -> String? in
                let entries = files.sorted { $0.key < $1.key }.map { ByteString(bytes: $0.value) }
                let report = try accountVerifyHistory(objects: AuthorityObjects(entries: entries, pending: [], heads: [], predecessor: []), nowMs: now)
                return report.account
            }.value
            guard verified == invite.account else {
                countFailure()
                throw Provisioner.Failure(text: "the invite's history does not verify as account \(pending.accountShort); nothing was stored")
            }
            var next = settings
            next.homePrefix = invite.homePrefix; next.slot = invite.slot; next.owner = OwnerChoice.none
            try await Task.detached {
                try FileManager.default.createDirectory(at: Paths.records, withIntermediateDirectories: true)
                try FolderMedium(folder: Paths.records).write(files.sorted { $0.key < $1.key }.map { MediumWrite(path: $0.key, bytes: $0.value) })
            }.value
            settings = next
            try Paths.save(settings)
            pendingInvite = nil
            record("joining account \(invite.account) at \(next.homeBase ?? "-") with \(files.count) verified history entries")
            openSession(request: nil)
            guard let session else { return }
            await session.restore()
            guard session.libraryID == invite.account else {
                throw Provisioner.Failure(text: "the stored history is for account \(session.libraryID ?? "none"), not \(invite.account)")
            }
            _ = try await requestPayload()
        }
    }

    // MARK: Attempts (spec §7.3 allows an existing side no more than 5 failed sessions an hour; the apps hold both sides to it)

    static let attemptLimit = 5
    private func recentFailures() -> [Date] { settings.failures.filter { Date.now.timeIntervalSince($0) < 3600 } }
    private func checkAttempts() throws {
        guard recentFailures().count < Self.attemptLimit else {
            throw Provisioner.Failure(text: "\(Self.attemptLimit) pairing attempts failed or were rejected in the last hour: wait before trying again")
        }
    }
    private func countFailure() {
        settings.failures = recentFailures() + [Date.now]
        try? Paths.save(settings)
    }

    /// This account's invite: the home and the `authority/` history, read off the main actor.
    func invitePayload() async throws -> String {
        guard let session, let account = session.libraryID, let slot = settings.slot else { throw SessionError.notReady }
        let history = try await Task.detached { () throws -> [String: Data] in
            let medium = FolderMedium(folder: Paths.records)
            var out: [String: Data] = [:]
            for entry in try medium.listing() where PairingPayload.isHistoryPath(entry.path) { out[entry.path] = try medium.read(entry.path) }
            return out
        }.value
        let text = try PairingPayload.encode(.init(homePrefix: settings.homePrefix, slot: slot, account: account, history: history))
        show(text, what: "invite (\(history.count) history entries, \(text.utf8.count) characters)")
        return text
    }

    func requestPayload() async throws -> String {
        guard let session else { throw SessionError.notReady }
        let text = try PairingPayload.encodeRequest(try await session.exportRequest())
        show(text, what: "request (\(text.utf8.count) characters)")
        return text
    }

    private func show(_ text: String, what: String) {
        shownPayload = text
        record("showing \(what)")
        #if DEBUG
        let url = Paths.outbox
        Task.detached { try? Data(text.utf8).write(to: url, options: .atomic) }
        #endif
    }

    func importRequest(_ text: String) async {
        await perform("Import request") {
            guard let session else { throw SessionError.notReady }
            try checkAttempts()
            pendingRequestText = nil
            let request: Data
            do { request = try PairingPayload.decodeRequest(text) } catch { countFailure(); throw error }
            try await session.importRequest(request)
            record("imported a request; waiting: \(session.requests.map { "\($0.label) \($0.pairingCode)" }.joined(separator: ", "))")
        }
    }

    /// The person says the code on this screen and on the joining device are the same.
    func confirmCodes(_ request: AccessRequest) { confirmedCodes.insert(request.id); record("codes confirmed for \(request.label) \(request.pairingCode)") }

    /// Discards a request: it is hidden from now on and counts as a failed attempt.
    func reject(_ request: AccessRequest) {
        confirmedCodes.remove(request.id)
        settings.rejected.insert(request.id)
        countFailure()
        record("rejected the request \(request.label) \(request.pairingCode)")
    }

    /// The requests waiting, without the ones the person rejected.
    var visibleRequests: [AccessRequest] { (session?.requests ?? []).filter { !settings.rejected.contains($0.id) } }

    func approve(_ request: AccessRequest) async {
        await perform("Approve \(request.pairingCode)") {
            guard let session else { throw SessionError.notReady }
            guard confirmedCodes.contains(request.id) else { throw Provisioner.Failure(text: "confirm that the codes match first") }
            try await session.approve(request)
            record("approved \(request.label) \(request.id)")
            await sync()
        }
    }

    func revoke(_ member: AccountMember) async {
        await perform("Revoke \(member.label)") {
            guard let session else { throw SessionError.notReady }
            try await session.revoke(memberID: member.id)
            record("revoked \(member.label) \(member.id)")
            await sync()
        }
    }

    func veto(_ pending: Pending) async {
        await perform("Veto") {
            guard let session else { throw SessionError.notReady }
            try await session.veto(pending.digest)
            record("vetoed \(pending.digest)")
        }
    }

    // MARK: Sync

    func sync() async {
        guard let session else { return }
        let ok = await session.syncNow()
        let faults = session.homeFaults.map(Self.describe)
        let issues = session.homeIssues.map { "\($0.problem)" }
        let sighting = observer.snapshot()
        var parts: [String] = ["phase \(session.phase)", "sync state \(session.syncState)"]
        if !faults.isEmpty { parts.append("faults: " + faults.joined(separator: "; ")) }
        if !issues.isEmpty { parts.append("issues: " + issues.joined(separator: "; ")) }
        if let refusal = sighting.lastRefusal, Date.now.timeIntervalSince(refusal.at) < 30 {
            parts.append("last refusal: \(refusal.status) \(refusal.method) \(refusal.path) \(refusal.detail)")
        }
        if let error = sighting.transportError { parts.append("transport: \(error)") }
        parts.append(sighting.head.map { "home head seq \($0.seq) issued \($0.issued)" } ?? "no head read yet (last: \(sighting.last.map { "\($0.status) \($0.method) \($0.path)" } ?? "-"))")
        let kind: SyncOutcome.Kind = !ok ? .failed : (faults.isEmpty && issues.isEmpty ? .complete : .incomplete)
        lastSync = SyncOutcome(at: .now, kind: kind, detail: parts.joined(separator: "\n"))
        record("sync \(kind.rawValue): \(parts.joined(separator: " | "))")
    }

    // MARK: Notes

    func reloadNotes() async {
        guard let session, session.hasUsableContent else { notes = []; notesProblem = nil; return }
        do {
            let labels = Dictionary(session.members.map { ($0.id, $0.label) }, uniquingKeysWith: { a, _ in a })
            let folded = try NotesFold.fold(viewJSON: try await session.view(namespace: NotesFold.namespace), labels: labels)
            notes = folded.notes; heldAndRefused = (folded.held, folded.refused); notesProblem = nil
        } catch {
            notesProblem = Self.message(error)
        }
    }

    func saveNote(id: String?, text: String, photo: Data?, keepPhoto: Note.Photo?, observed: ObservedRevision) async -> Bool {
        var saved = false
        await perform(id == nil ? "Add note" : "Save note") {
            guard let session else { throw SessionError.notReady }
            let noteID = id ?? UUID().uuidString.lowercased()
            var attached = keepPhoto
            if let photo {
                let blob = try await session.putBlob(photo, namespace: NotesFold.namespace, mediaType: "image/jpeg", reference: noteID, required: true)
                attached = .init(digest: blob.digest, mediaType: blob.mediaType, size: blob.size)
            }
            let command = try DomainCommand(namespace: NotesFold.namespace, kind: NotesFold.kind,
                                            payloadJSON: try NotesFold.payload(id: noteID, text: text, photo: attached))
            let receipt = try await session.perform(command, observed: observed)
            record("note \(noteID.prefix(8)) written: \(receipt)")
            saved = true
            await reloadNotes()
            session.requestSync()
        }
        return saved
    }

    func deleteNote(_ note: Note) async {
        await perform("Delete note") {
            guard let session else { throw SessionError.notReady }
            let command = try DomainCommand(namespace: NotesFold.namespace, kind: NotesFold.kind,
                                            payloadJSON: try NotesFold.payload(id: note.id, text: "", photo: nil, deleted: true))
            let receipt = try await session.perform(command, observed: session.observedRevision)
            record("note \(note.id.prefix(8)) deleted: \(receipt)")
            await reloadNotes()
            session.requestSync()
        }
    }

    func photo(_ note: Note) async throws -> Data {
        guard let session, let photo = note.photo else { throw SessionError.notReady }
        return try await session.blobData(namespace: NotesFold.namespace, digest: photo.digest)
    }

    // MARK: Lock, sign out, reset

    func lock() async { await session?.lock(); record("locked") }
    func unlock() async { await session?.unlock(); record("unlock: phase \(session.map { "\($0.phase)" } ?? "-")") }

    /// Wipes this device's account: the records, the session's private state, the member, owner and device keys. The
    /// home settings stay. The account itself is unchanged (an owner device can revoke this member).
    func signOut() async {
        await perform("Sign out") {
            if let session { session.stopSync(); await session.lock() }
            session = nil; notes = []; lastSync = nil; shownPayload = nil; seen = nil
            observer.reset()
            try await Self.wipeAccount()
            var next = settings
            next.slot = nil; next.owner = nil; next.passkey = nil
            settings = next
            try Paths.save(settings)
            record("signed out: local account state wiped")
        }
    }

    /// Sign out, and forget the settings and the log too: the app is as freshly installed.
    func resetDevice() async {
        await perform("Reset this device") {
            if let session { session.stopSync(); await session.lock() }
            session = nil; notes = []; lastSync = nil; shownPayload = nil; seen = nil
            observer.reset()
            try await Self.wipeAccount()
            try await Task.detached {
                for url in [Paths.root, Paths.outbox] where FileManager.default.fileExists(atPath: url.path) {
                    try FileManager.default.removeItem(at: url)
                }
            }.value
            settings = Settings()
            log.removeAll()
            record("device reset to the build's defaults")
        }
    }

    private static func wipeAccount() async throws {
        let services = [service, deviceKeyService]
        try await Task.detached {
            for service in services {
                let status = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service] as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else { throw Provisioner.Failure(text: "Keychain delete: \(status)") }
            }
            if FileManager.default.fileExists(atPath: Paths.account.path) { try FileManager.default.removeItem(at: Paths.account) }
        }.value
    }

    // MARK: Links

    /// `colophontest://join?p=CTJ1.…` and `colophontest://request?p=CTR1.…` (QR codes and scripted runs).
    func open(_ url: URL) async {
        guard url.scheme == "colophontest", let p = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "p" })?.value else { return }
        record("opened link \(url.host ?? "-")")
        switch url.host {
        // A link only fills a screen the person must confirm: it never joins, imports or approves by itself.
        case "join" where settings.slot == nil: await prepareJoin(p)
        case "request" where isOwner: pendingRequestText = p; record("a request arrived by link: shown in Devices, not imported")
        default: actionError = "This link does not fit this device's state (\(url.host ?? "-"))."
        }
    }
}

/// A device that joined an account holds no owner key: every owner step fails plainly.
struct NoOwner: AsyncKeyProvider {
    var form: KeyForm { .raw }
    func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion? { throw SessionError.ownerRequired }
    func prf(salt: Data) async throws -> SecretBytes? { throw SessionError.ownerRequired }
    func publicKeys() async throws -> PublicKeys { throw SessionError.ownerRequired }
    func sign(body: Data) async throws -> Data { throw SessionError.ownerRequired }
    func sharedSecret(peer: Data) async throws -> SecretBytes { throw SessionError.ownerRequired }
    func keyDescriptor() async throws -> KeyDescriptorView { throw SessionError.ownerRequired }
}

/// The system ceremonies, keeping the registration's attestation object (public) so the descriptor can be rebuilt.
final class RecordingCeremonies: WebAuthnCeremonies, @unchecked Sendable {
    private let base = SystemWebAuthnCeremonies()
    private let lock = NSLock()
    private var stored: Data?
    var attestation: Data? { lock.withLock { stored } }
    var supportsSecurityKeys: Bool { base.supportsSecurityKeys }
    func supportsPRF(kind: CredentialKind) -> Bool { base.supportsPRF(kind: kind) }
    func register(kind: CredentialKind, rpID: String, userID: Data, userName: String, challenge: Data) async throws -> Registration {
        let registration = try await base.register(kind: kind, rpID: rpID, userID: userID, userName: userName, challenge: challenge)
        lock.withLock { stored = registration.attestationObject }
        return registration
    }
    func assert(kind: CredentialKind, rpID: String, credential: Data, challenge: Data, prfSalt: Data?, requireVerification: Bool) async throws -> AssertionResult {
        try await base.assert(kind: kind, rpID: rpID, credential: credential, challenge: challenge, prfSalt: prfSalt, requireVerification: requireVerification)
    }
}

extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}
