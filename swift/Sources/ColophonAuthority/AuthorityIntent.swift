import ColophonCore
import ColophonStore
import Foundation

/// One authority write this device attempted. The file holds no key material: a later read of the
/// history either finds these body digests or the device signs the same decision again.
public struct AuthorityWriteIntent: Codable, Sendable, Equatable {
  public var libraryID: String
  public var kind: String
  public var memberID: String
  public var namespaces: [String]
  public var write: Bool
  public var caveats: [Caveat]
  public var sequences: [Int]
  public var digests: [String]
  public var label: String?
  public var role: String?
  public var custody: String?
  public var keyOperator: String?
  public var grantSequence: Int?
  public var app: String?
  public var device: String?
  /// The original grant deadline. Absent in older intent files and for permanent grants.
  public var expires: Date?
  /// True only when the original grant batch created a missing namespace's first epoch.
  /// Older intents never imply permission to create one.
  public var createMissingEpochs: Bool?
  /// Public epoch provenance for an interrupted revoke batch; never contains namespace keys.
  public var revocationEpochs: [String: Int]?

  public init(libraryID: String, kind: String, memberID: String, namespaces: [String], write: Bool, caveats: [Caveat],
    sequences: [Int], digests: [String], label: String?, role: String?, custody: String?, keyOperator: String?,
    grantSequence: Int?, app: String?, device: String?, expires: Date? = nil, createMissingEpochs: Bool? = nil,
    revocationEpochs: [String: Int]? = nil)
  {
    self.libraryID = libraryID
    self.kind = kind
    self.memberID = memberID
    self.namespaces = namespaces
    self.write = write
    self.caveats = caveats
    self.sequences = sequences
    self.digests = digests
    self.label = label
    self.role = role
    self.custody = custody
    self.keyOperator = keyOperator
    self.grantSequence = grantSequence
    self.app = app
    self.device = device
    self.expires = expires
    self.createMissingEpochs = createMissingEpochs
    self.revocationEpochs = revocationEpochs
  }

  /// Approval, revocation and finish batches only. A keyring change carries slots, so it is not an intent.
  static func capture(libraryID: String, drafts: [AuthorityEntry], state: AuthorityState) -> AuthorityWriteIntent? {
    guard let first = drafts.first else { return nil }
    let restAreShares = drafts.dropFirst().allSatisfy { $0.kind == .shareKey }
    switch first.kind {
    case .grant where restAreShares:
      guard let member = first.member else { return nil }
      let createdEpoch = drafts.dropFirst().contains { draft in
        guard let namespace = draft.namespace else { return false }
        return first.namespaces?.contains(namespace) == true && state.allEpochs(of: namespace).isEmpty && draft.epoch == 1
      }
      return AuthorityWriteIntent(libraryID: libraryID, kind: "approve", memberID: member.id,
        namespaces: first.namespaces ?? [], write: first.write ?? false, caveats: first.caveats ?? [], sequences: [],
        digests: [], label: first.label, role: first.role?.rawValue, custody: first.custody?.rawValue,
        keyOperator: first.keyOperator, grantSequence: nil, app: first.app, device: first.device, expires: first.expires,
        createMissingEpochs: createdEpoch ? true : nil)
    case .revoke where restAreShares:
      guard let memberID = first.memberID else { return nil }
      var epochs: [String: Int] = [:]
      for draft in drafts.dropFirst() {
        if let namespace = draft.namespace, let epoch = draft.epoch { epochs[namespace] = epoch }
      }
      return AuthorityWriteIntent(libraryID: libraryID, kind: "revoke", memberID: memberID, namespaces: [], write: false,
        caveats: [], sequences: [], digests: [], label: nil, role: nil, custody: nil, keyOperator: nil,
        grantSequence: nil, app: nil, device: nil, revocationEpochs: epochs.isEmpty ? nil : epochs)
    case .shareKey where drafts.allSatisfy({ $0.kind == .shareKey }):
      guard let memberID = first.memberID else { return nil }
      return AuthorityWriteIntent(libraryID: libraryID, kind: "finish", memberID: memberID, namespaces: [], write: false,
        caveats: [], sequences: [], digests: [], label: nil, role: nil, custody: nil, keyOperator: nil,
        grantSequence: state.members[memberID]?.current?.seq, app: nil, device: nil)
    default:
      return nil
    }
  }
}

/// Pending intents live in the app's own home, one file per library. The file is a list so a second
/// approval does not replace the first. An older file holding one intent is still read.
public struct AuthorityIntentStore: Sendable {
  public let directory: URL
  // Holders save on workers while the session confirms on its actor. One process lock makes
  // every local read/modify/write atomic, including the latest-decision fence.
  private static let lock = NSLock()

  public init(directory: URL) { self.directory = directory }

  public func save(_ intent: AuthorityWriteIntent) throws {
    try update(libraryID: intent.libraryID) { saved in
      if intent.kind == "approve" || intent.kind == "revoke" {
        // A fresh explicit decision supersedes every earlier local decision for this member.
        saved.intents.removeAll { $0.memberID == intent.memberID }
        saved.confirmed?.removeAll { $0.memberID == intent.memberID }
      }
      if let index = saved.intents.firstIndex(where: { $0.kind == intent.kind && $0.memberID == intent.memberID }) {
        saved.intents[index] = intent
      } else {
        saved.intents.append(intent)
      }
    }
  }

  public func load(libraryID: String) -> [AuthorityWriteIntent] {
    Self.lock.withLock { read(libraryID: libraryID).intents }
  }

  /// Local confirmation is a receipt, not provider finality. Receipts are never replayed.
  public func loadConfirmed(libraryID: String) -> [AuthorityWriteIntent] {
    Self.lock.withLock { read(libraryID: libraryID).confirmed ?? [] }
  }

  public func loadSignedBatches(libraryID: String) -> [AuthoritySignedBatch] {
    Self.lock.withLock { read(libraryID: libraryID).signedBatches ?? [] }
  }

  /// Stores only records already destined for the shared folder: signatures, public metadata,
  /// and encrypted envelopes. No vault seed or unsealed namespace key is journaled.
  public func saveSignedBatch(_ batch: AuthoritySignedBatch) throws {
    try update(libraryID: batch.libraryID) { saved in
      let existing = saved.signedBatches ?? []
      guard existing.allSatisfy({ $0.id == batch.id }) else {
        throw ColophonError.keysCantDoThis(String(localized: "A previous library key change isn't finished. Finish it before changing keys again."))
      }
      saved.confirmed?.removeAll { $0.kind == "keyring" }
      saved.signedBatches = [batch]
    }
  }

  public func confirmSignedBatch(_ batch: AuthoritySignedBatch) throws {
    try update(libraryID: batch.libraryID) { saved in
      guard saved.signedBatches?.contains(where: { $0.id == batch.id }) == true else { return }
      saved.signedBatches?.removeAll { $0.id == batch.id }
      var receipts = saved.confirmed ?? []
      receipts.removeAll { $0.kind == "keyring" }
      receipts.append(AuthorityWriteIntent(libraryID: batch.libraryID, kind: "keyring", memberID: "keyring",
        namespaces: [], write: false, caveats: [], sequences: batch.records.indices.map { batch.baseSequence + $0 + 1 },
        digests: batch.records.map { Canonical.digest($0.body) }, label: nil, role: nil, custody: nil, keyOperator: nil,
        grantSequence: nil, app: nil, device: nil))
      saved.confirmed = receipts
    }
  }

  public func confirm(_ intent: AuthorityWriteIntent) throws {
    try update(libraryID: intent.libraryID) { saved in
      guard saved.intents.contains(intent) else { return }
      saved.intents.removeAll { $0 == intent }
      if intent.kind == "approve" || intent.kind == "revoke" {
        var receipts = saved.confirmed ?? []
        receipts.removeAll { $0.memberID == intent.memberID }
        receipts.append(intent)
        saved.confirmed = receipts
      }
    }
  }

  public func removeConfirmed(_ receipt: AuthorityWriteIntent) throws {
    try update(libraryID: receipt.libraryID) { saved in
      saved.confirmed?.removeAll { $0 == receipt }
    }
  }

  public func remove(libraryID: String, kind: String, memberID: String) throws {
    try update(libraryID: libraryID) { saved in
      saved.intents.removeAll { $0.kind == kind && $0.memberID == memberID }
    }
  }

  public func clear(libraryID: String) {
    Self.lock.withLock { try? FileManager.default.removeItem(at: file(libraryID)) }
  }

  private func file(_ libraryID: String) -> URL { directory.appending(path: libraryID + ".json") }

  private func read(libraryID: String) -> AuthorityIntentList {
    guard let data = try? Data(contentsOf: file(libraryID)) else { return AuthorityIntentList(intents: []) }
    if let list = try? Canonical.decode(AuthorityIntentList.self, from: data) { return list }
    if let one = try? Canonical.decode(AuthorityWriteIntent.self, from: data) { return AuthorityIntentList(intents: [one]) }
    return AuthorityIntentList(intents: [])
  }

  private func write(libraryID: String, saved: AuthorityIntentList) throws {
    if saved.intents.isEmpty, saved.confirmed?.isEmpty != false, saved.signedBatches?.isEmpty != false {
      try? FileManager.default.removeItem(at: file(libraryID))
      return
    }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try PrivateAtomicFile.write(Canonical.encode(saved), to: file(libraryID))
  }

  private func update(libraryID: String, _ change: (inout AuthorityIntentList) throws -> Void) throws {
    try Self.lock.withLock {
      var saved = read(libraryID: libraryID)
      try change(&saved)
      try write(libraryID: libraryID, saved: saved)
    }
  }
}

private struct AuthorityIntentList: Codable, Sendable {
  var intents: [AuthorityWriteIntent]
  var confirmed: [AuthorityWriteIntent]? = nil
  var signedBatches: [AuthoritySignedBatch]? = nil
}

/// A fully signed keyring change, anchored to the exact authority body it extends. Its immutable
/// tail can finish after process death without reopening the old vault or signing anything else.
public struct AuthoritySignedBatch: Codable, Sendable {
  public let id: String
  public let libraryID: String
  public let baseSequence: Int
  public let baseDigest: String
  public let records: [SignedRecord]

  public init(libraryID: String, baseSequence: Int, baseDigest: String, records: [SignedRecord]) throws {
    self.libraryID = libraryID
    self.baseSequence = baseSequence
    self.baseDigest = baseDigest
    self.records = records
    id = Canonical.digest(try Canonical.encode(records))
  }
}

/// What a device should do when its intent is not the history that won.
public enum AuthorityIntentAction: Sendable, Equatable {
  case clear
  case keep
  case approve(namespaces: [String], write: Bool, caveats: [Caveat])
  case revoke
  case finish(grantSequence: Int)
}

public enum AuthorityIntentRebase {
  public static func read(store: any RecordStore) throws -> [SignedRecord] {
    var records: [SignedRecord] = []
    var sequence = 1
    while let data = try store.read(LibraryPath.authority(sequence)) {
      records.append(try Canonical.decode(SignedRecord.self, from: data))
      sequence += 1
    }
    return records
  }

  /// True only when every stored sequence still holds the body this device wrote.
  public static func confirmed(_ intent: AuthorityWriteIntent, records: [SignedRecord]) -> Bool {
    guard !intent.sequences.isEmpty, intent.sequences.count == intent.digests.count else { return false }
    for (sequence, digest) in zip(intent.sequences, intent.digests) {
      let index = sequence - 1
      guard records.indices.contains(index), Canonical.digest(records[index].body) == digest else { return false }
    }
    return true
  }

  /// `requestsComplete` is false while the request folder is still arriving. A missing request then
  /// stays pending. Once the folder is complete, a request that is not there is gone.
  public static func action(_ intent: AuthorityWriteIntent, state: AuthorityState, pendingMemberIDs: Set<String>,
    requestsComplete: Bool = false) -> AuthorityIntentAction
  {
    switch intent.kind {
    case "revoke":
      guard let member = state.members[intent.memberID] else { return .clear }
      if member.revokedAt != nil {
        return state.incompleteRevocationNamespaces(for: intent.memberID).isEmpty ? .clear : .revoke
      }
      // sequences are the writes this intent attempted, so the head it was based on is one before
      // the earliest. A grant newer than that head already replaced the decision.
      if let grant = member.current, let base = intent.sequences.min().map({ $0 - 1 }), grant.seq > base {
        return .clear
      }
      return .revoke
    case "finish":
      guard let member = state.members[intent.memberID], member.revokedAt == nil, let grant = member.current else {
        return .clear
      }
      if state.missingKeyShares(for: intent.memberID).isEmpty { return .clear }
      return .finish(grantSequence: grant.seq)
    default:
      if let member = state.members[intent.memberID], member.revokedAt != nil || member.current != nil { return .clear }
      if pendingMemberIDs.contains(intent.memberID) {
        return .approve(namespaces: intent.namespaces, write: intent.write, caveats: intent.caveats)
      }
      if requestsComplete { return .clear }
      return .keep
    }
  }
}
