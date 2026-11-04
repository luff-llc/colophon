import ColophonAuthority
import ColophonCore
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation
import Testing
@testable import ColophonListening

struct PlaybackProgressJournalTests {
  private struct Payload: Codable, Equatable, Sendable {
    let episode: String
    let seconds: Double
    var observedPosition: String? = nil
    var observedState: String? = nil
    var intendedInProgress = true
  }
  private typealias Journal = PlaybackProgressJournal<Payload>

  private struct Fixture {
    let directory = FileManager.default.temporaryDirectory.appending(path: "playback-journal-" + UUID().uuidString)
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let member = SoftwareIdentity()
    let replica: Replica
    var file: URL { directory.appending(path: "playback-progress.journal") }

    init() throws {
      _ = try AuthorityHolder.create(in: store, label: "Synthetic", root: root,
        firstMember: member.publicIdentity, memberLabel: "Fixture", role: .app, custody: .software,
        namespaces: [Podcasts.namespace])
      replica = Replica(store: store, identity: member)
    }
    func holder() throws -> AuthorityHolder { try AuthorityHolder(log: replica.log, root: root) }
    func bytes() throws -> Data { try Data(contentsOf: file) }
    func envelope() throws -> PlaybackProgressJournalEnvelope {
      try Canonical.decode(PlaybackProgressJournalEnvelope.self, from: bytes())
    }
    func write(_ envelope: PlaybackProgressJournalEnvelope) throws {
      try Canonical.encode(envelope).write(to: file, options: .atomic)
    }
  }

  /// Every mutable field is protected by `lock`; software key material is immutable.
  private final class GatedIdentity: Identity, @unchecked Sendable {
    let base: SoftwareIdentity
    private let lock = NSLock()
    private var blocked = false
    init(_ base: SoftwareIdentity) { self.base = base }
    func block(_ value: Bool) { lock.withLock { blocked = value } }
    private func check() throws {
      if lock.withLock({ blocked }) { throw NSError(domain: NSOSStatusErrorDomain, code: -25308) }
    }
    var publicIdentity: PublicIdentity { base.publicIdentity }
    var custody: KeyCustody { .software }
    func sign(_ bytes: Data) throws -> Data { try check(); return try base.sign(bytes) }
    func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
      try check(); return try base.sharedSecret(with: peer)
    }
  }

  /// The only mutable flag is lock protected, including accesses from injected file closures.
  private final class FailureSwitch: @unchecked Sendable {
    private let lock = NSLock()
    private var enabled = false
    func enable() { lock.withLock { enabled = true } }
    var isEnabled: Bool { lock.withLock { enabled } }
  }

  @Test func multiplePendingEpisodesSurviveReopenWithoutPlaintextOrLibraryWrites() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let before = fixture.store.snapshot
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica)
    let first = Payload(episode: "private episode alpha", seconds: 40)
    let second = Payload(episode: "private episode beta", seconds: 70)
    let receipt = try journal.replace(id: "alpha", payload: first, expecting: nil)
    try journal.replace(id: "beta", payload: second, expecting: nil)
    let bytes = try fixture.bytes()
    #expect(bytes.range(of: Data(first.episode.utf8)) == nil)
    let fields = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    let names = Set(fields.keys)
    let expectedNames: Set<String> = ["ticket", "ciphertext"]
    #expect(names == expectedNames)
    journal.invalidate()

    let reopened = try Journal(directory: fixture.directory, replica: fixture.replica)
    let restored = try reopened.records()
    #expect(restored["alpha"]?.payload == first)
    #expect(restored["beta"]?.payload == second)
    #expect(restored["alpha"]?.revision == receipt.revision)
    #expect(reopened.context.member == fixture.member.publicIdentity)
    let after = fixture.store.snapshot
    #expect(after == before)
    let files = try FileManager.default.contentsOfDirectory(atPath: fixture.directory.path)
    let expectedFiles = ["playback-progress.journal"]
    #expect(files == expectedFiles)
  }

  @Test func cancellationAndAcknowledgementUseExactRevisionBarriers() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica)
    let cancelled = try journal.tombstone(id: "episode", expecting: nil)
    #expect(throws: PlaybackProgressJournalError.staleRevision) {
      try journal.replace(id: "episode", payload: Payload(episode: "old", seconds: 40), expecting: nil)
    }
    let replacement = try journal.replace(id: "episode", payload: Payload(episode: "restart", seconds: 0),
      expecting: cancelled.revision)
    #expect(throws: PlaybackProgressJournalError.staleRevision) {
      try journal.tombstone(id: "episode", expecting: cancelled.revision)
    }
    let retained = try journal.records()
    #expect(retained["episode"]?.revision == replacement.revision)
    #expect(retained["episode"]?.payload?.seconds == 0)
    let acknowledged = try journal.tombstone(id: "episode", expecting: replacement.revision)
    let bytes = try fixture.bytes()
    let repeated = try journal.tombstone(id: "episode", expecting: acknowledged.revision)
    #expect(repeated.revision == acknowledged.revision)
    let after = try fixture.bytes()
    #expect(after == bytes)
  }

  @Test func startupCompactionRetainsLivePayloadAndRejectsOldReceipts() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica)
    let live = Payload(episode: "live", seconds: 55)
    let old = try journal.replace(id: "live", payload: live, expecting: nil)
    let later = Payload(episode: "latest", seconds: 75)
    try journal.replace(id: "alphabetically first", payload: later, expecting: nil)
    try journal.tombstone(id: "cancelled", expecting: nil)
    let priorTicket = try fixture.envelope().ticket
    journal.invalidate()

    let reopened = try Journal(directory: fixture.directory, replica: fixture.replica)
    let restored = try reopened.records()
    let retained = try #require(restored["live"])
    #expect(restored.count == 2)
    let latest = try #require(restored["alphabetically first"])
    #expect(latest.payload == later)
    #expect(latest.revision.sequence > retained.revision.sequence)
    #expect(restored["cancelled"] == nil)
    #expect(retained.payload == live)
    #expect(retained.revision.generation != old.revision.generation)
    let nextTicket = try fixture.envelope().ticket
    #expect(nextTicket != priorTicket)
    #expect(throws: PlaybackProgressJournalError.staleRevision) {
      try reopened.tombstone(id: "live", expecting: old.revision)
    }
    try reopened.tombstone(id: "live", expecting: retained.revision)
  }

  @Test func everyMutationUsesAFreshNonceWithExactStoredTicketAsAAD() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica)
    let first = try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 20), expecting: nil)
    let before = try fixture.envelope()
    try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 30), expecting: first.revision)
    let after = try fixture.envelope()
    let firstNonce = Data(try AES.GCM.SealedBox(combined: before.ciphertext).nonce)
    let secondNonce = Data(try AES.GCM.SealedBox(combined: after.ciphertext).nonce)
    #expect(firstNonce != secondNonce)
    #expect(before.ticket == after.ticket)
    journal.invalidate()
    // This is still a valid signed record. Re-encoding it would discard the leading
    // whitespace, but AAD must authenticate the exact stored signed-ticket bytes.
    var ticketWithWhitespace = Data(" ".utf8)
    ticketWithWhitespace.append(after.ticket)
    try fixture.write(.init(ticket: ticketWithWhitespace, ciphertext: after.ciphertext))
    let retained = try fixture.bytes()
    #expect(throws: PlaybackProgressJournalError.invalidCiphertext) {
      try Journal(directory: fixture.directory, replica: fixture.replica)
    }
    let unchanged = try fixture.bytes()
    #expect(unchanged == retained)
  }

  @Test(arguments: ["signature", "ciphertext", "purpose", "version", "namespace", "library", "agreement", "generation", "wrapped key"])
  func tamperedTicketOrCiphertextFailsClosedAndRetainsBytes(field: String) throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica)
    try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 40), expecting: nil)
    journal.invalidate()
    let envelope = try fixture.envelope()
    let signed = try Canonical.decode(SignedRecord.self, from: envelope.ticket)
    let original = try Canonical.decode(PlaybackProgressJournalTicket.self, from: signed.body)
    let changed: PlaybackProgressJournalEnvelope
    let expected: PlaybackProgressJournalError
    if field == "signature" {
      var signature = signed.signature
      signature[signature.startIndex] ^= 1
      changed = .init(ticket: try Canonical.encode(SignedRecord(body: signed.body, signature: signature)),
        ciphertext: envelope.ciphertext)
      expected = .invalidTicket
    } else if field == "ciphertext" {
      var ciphertext = envelope.ciphertext
      ciphertext[ciphertext.startIndex] ^= 1
      changed = .init(ticket: envelope.ticket, ciphertext: ciphertext)
      expected = .invalidCiphertext
    } else {
      let member = field == "agreement" ? PublicIdentity(signing: original.member.signing,
        agreement: SoftwareIdentity().publicIdentity.agreement) : original.member
      if field == "agreement" { #expect(member.id == original.member.id) }
      let wrapped = field == "wrapped key"
        ? try SealedKey(SymmetricKey(size: .bits256), to: original.member) : original.key
      let modified = PlaybackProgressJournalTicket(
        purpose: field == "purpose" ? "another purpose" : original.purpose,
        version: field == "version" ? 2 : original.version,
        namespace: field == "namespace" ? "another.namespace" : original.namespace,
        libraryID: field == "library" ? "another library" : original.libraryID,
        member: member, generation: field == "generation" ? UUID().uuidString.lowercased() : original.generation,
        key: wrapped)
      let validlySigned = try SignedRecord(signing: Canonical.encode(modified), with: fixture.member)
      changed = .init(ticket: try Canonical.encode(validlySigned), ciphertext: envelope.ciphertext)
      expected = field == "generation" || field == "wrapped key" ? .invalidCiphertext : .wrongContext
    }
    try fixture.write(changed)
    let retained = try fixture.bytes()
    #expect(throws: expected) { try Journal(directory: fixture.directory, replica: fixture.replica) }
    let unchanged = try fixture.bytes()
    #expect(unchanged == retained)
  }

  @Test(arguments: ["malformed", "missing ticket", "missing ciphertext"])
  func malformedEnvelopeIsNeverReplacedByAnEmptyJournal(kind: String) throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    try FileManager.default.createDirectory(at: fixture.directory, withIntermediateDirectories: true)
    let invalid = kind == "malformed" ? "not JSON" : kind == "missing ticket" ? "{\"ciphertext\":\"\"}" : "{\"ticket\":\"\"}"
    let retained = Data(invalid.utf8)
    try retained.write(to: fixture.file)
    #expect(throws: PlaybackProgressJournalError.invalidTicket) {
      try Journal(directory: fixture.directory, replica: fixture.replica)
    }
    let unchanged = try fixture.bytes()
    #expect(unchanged == retained)
  }

  @Test func pendingEnrollmentCannotOpenJournalButApprovedMemberCanThenRevocationStillDenies() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let joining = SoftwareIdentity()
    let requester = Replica(store: fixture.store, identity: joining)
    let request = try requester.requestEnrollment(label: "Taupe joining", role: .app, namespaces: [Podcasts.namespace])
    #expect(throws: PlaybackProgressJournalError.noCurrentAccess) {
      try Journal(directory: fixture.directory, replica: requester)
    }
    let pendingCreatedFile = FileManager.default.fileExists(atPath: fixture.file.path)
    #expect(!pendingCreatedFile)
    let holder = try fixture.holder()
    try holder.approve(request, namespaces: [Podcasts.namespace], write: true)
    let journal = try Journal(directory: fixture.directory, replica: requester)
    try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 73), expecting: nil)
    let saved = try journal.records()
    #expect(saved["episode"]?.payload?.seconds == 73)
    journal.invalidate()
    let retained = try fixture.bytes()
    try holder.revoke(joining.id, seen: [])
    #expect(throws: PlaybackProgressJournalError.noCurrentAccess) {
      try Journal(directory: fixture.directory, replica: requester)
    }
    let afterRevocation = try fixture.bytes()
    #expect(afterRevocation == retained)
  }

  @Test(arguments: ["revoked", "read only", "wrong namespace", "expired"])
  func currentGrantIsRequiredEvenForAnAuthenticJournal(access: String) throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica)
    try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 40), expecting: nil)
    journal.invalidate()
    let retained = try fixture.bytes()
    let holder = try fixture.holder()
    if access == "revoked" { try holder.revoke(fixture.member.id, seen: []) }
    else {
      try holder.admit(fixture.member.publicIdentity, label: "Fixture", role: .app, custody: .software,
        namespaces: access == "wrong namespace" ? [] : [Podcasts.namespace], write: access != "read only",
        expires: access == "expired" ? .distantPast : nil)
    }
    #expect(throws: PlaybackProgressJournalError.noCurrentAccess) {
      try Journal(directory: fixture.directory, replica: fixture.replica)
    }
    let unchanged = try fixture.bytes()
    #expect(unchanged == retained)
  }

  @Test func anotherCurrentLibraryCannotAdoptTheStoredIdentityOrLibrary() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica)
    journal.invalidate()
    let retained = try fixture.bytes()
    let other = MemoryStore()
    _ = try AuthorityHolder.create(in: other, label: "Other", root: SoftwareIdentity(),
      firstMember: fixture.member.publicIdentity, memberLabel: "Fixture", role: .app, custody: .software,
      namespaces: [Podcasts.namespace])
    let otherReplica = Replica(store: other, identity: fixture.member)
    #expect(throws: PlaybackProgressJournalError.wrongContext) {
      try Journal(directory: fixture.directory, replica: otherReplica)
    }
    let unchanged = try fixture.bytes()
    #expect(unchanged == retained)
  }

  @Test(arguments: [false, true])
  func protectedKeyNeverCreatesAFallbackAndExistingBytesRecover(existing: Bool) throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let identity = GatedIdentity(fixture.member)
    let replica = Replica(store: fixture.store, identity: identity)
    var retained: Data?
    if existing {
      let journal = try Journal(directory: fixture.directory, replica: replica)
      try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 40), expecting: nil)
      journal.invalidate()
      retained = try fixture.bytes()
    }
    identity.block(true)
    do {
      _ = try Journal(directory: fixture.directory, replica: replica)
      Issue.record("A protected member key must not open or prepare a journal")
    } catch {
      let failure = error as NSError
      #expect(failure.domain == NSOSStatusErrorDomain)
      #expect(failure.code == -25308)
    }
    if let retained {
      let unchanged = try fixture.bytes()
      #expect(unchanged == retained)
    } else { #expect(!FileManager.default.fileExists(atPath: fixture.file.path)) }
    identity.block(false)
    let recovered = try Journal(directory: fixture.directory, replica: replica)
    let records = try recovered.records()
    let expectedSeconds: Double? = existing ? 40 : nil
    #expect(records["episode"]?.payload?.seconds == expectedSeconds)
  }

  @Test func limitsRetainExistingDataAndCompactionReclaimsCancelledCapacity() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let limits = Journal.Limits(maximumRecords: 1, maximumPlaintextBytes: 512)
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica, limits: limits)
    let first = try journal.replace(id: "first", payload: Payload(episode: "first", seconds: 10), expecting: nil)
    let retained = try fixture.bytes()
    #expect(throws: PlaybackProgressJournalError.limitExceeded) {
      try journal.replace(id: "second", payload: Payload(episode: "second", seconds: 20), expecting: nil)
    }
    #expect(throws: PlaybackProgressJournalError.limitExceeded) {
      try journal.replace(id: "first", payload: Payload(episode: String(repeating: "x", count: 2_000), seconds: 30),
        expecting: first.revision)
    }
    let unchanged = try fixture.bytes()
    #expect(unchanged == retained)
    try journal.tombstone(id: "first", expecting: first.revision)
    journal.invalidate()
    let reopened = try Journal(directory: fixture.directory, replica: fixture.replica, limits: limits)
    try reopened.replace(id: "second", payload: Payload(episode: "second", seconds: 20), expecting: nil)
    let restored = try reopened.records()
    #expect(restored.count == 1)
    #expect(restored["second"]?.payload?.seconds == 20)
  }

  @Test func oversizedExistingFileIsRetainedBeforeDecoding() throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    try FileManager.default.createDirectory(at: fixture.directory, withIntermediateDirectories: true)
    let retained = Data(repeating: 42, count: 1_024)
    try retained.write(to: fixture.file)
    #expect(throws: PlaybackProgressJournalError.limitExceeded) {
      try Journal(directory: fixture.directory, replica: fixture.replica,
        limits: .init(maximumFileBytes: 512))
    }
    let unchanged = try fixture.bytes()
    #expect(unchanged == retained)
  }

  @Test(arguments: [false, true])
  func uncertainReplacementBlocksHandleAndReopenReadsActualCommittedBytes(afterCommit: Bool) throws {
    let fixture = try Fixture()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let failure = FailureSwitch()
    let files = PlaybackProgressJournalFiles(read: PlaybackProgressJournalFiles.live.read, write: { file, data in
      if failure.isEnabled, !afterCommit { throw CocoaError(.fileWriteUnknown) }
      try PlaybackProgressJournalFiles.live.write(file, data)
      if failure.isEnabled, afterCommit { throw CocoaError(.fileWriteUnknown) }
    })
    let journal = try Journal(directory: fixture.directory, replica: fixture.replica, limits: .init(), files: files)
    let first = try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 20), expecting: nil)
    let before = try fixture.bytes()
    failure.enable()
    #expect(throws: CocoaError.self) {
      try journal.replace(id: "episode", payload: Payload(episode: "episode", seconds: 40), expecting: first.revision)
    }
    #expect(throws: PlaybackProgressJournalError.unavailable) { try journal.records() }
    #expect(throws: PlaybackProgressJournalError.unavailable) {
      try journal.tombstone(id: "episode", expecting: first.revision)
    }
    let reopened = try Journal(directory: fixture.directory, replica: fixture.replica)
    let restored = try reopened.records()
    #expect(restored["episode"]?.payload?.seconds == (afterCommit ? 40 : 20))
    if !afterCommit {
      let unchanged = try fixture.bytes()
      #expect(unchanged == before)
    }
  }
}
