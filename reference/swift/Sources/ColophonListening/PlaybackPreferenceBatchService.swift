import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// Wire validation for one signed, all-or-nothing preference change. Playback defaults and
/// resolution remain in MarginaliaReaderCore.PlaybackPreferences/ListeningShortcuts; this type
/// only rejects values that those resolvers would ignore. Colophon does not depend on ReaderCore.
public enum PlaybackPreferenceBatch {
  public static let kind = "preferences.batch"
  public static let maximumKeys = 15
  public static let maximumBodyBytes = 8_192

  public struct Change: Sendable, Equatable {
    public enum Scope: Sendable, Equatable { case global, show(String), episode(String) }
    public let key: String
    public let field: String
    public let scope: Scope
    public let value: String
  }

  public struct Body: Sendable, Equatable {
    public let commandID: String
    public let commandDigest: String
    public let changes: [Change]
    public let expected: [String: String?]
  }

  private static let playbackFields: Set<String> = [
    "speed", "backward", "forward", "shortenSilence", "levelSpeech", "monoAudio",
    "skipSponsors", "skipDetectedSponsors", "skipAdChapters",
  ]
  private static let shortcutFields: Set<String> = [
    "doublePress", "triplePress", "carUsesChapters", "sentenceRewind", "smartResume", "markButton",
  ]
  private static let speeds: Set<Double> = [
    0.75, 0.8, 0.85, 0.9, 0.95, 1, 1.05, 1.1, 1.15, 1.2, 1.25, 1.3, 1.35, 1.4, 1.45, 1.5,
    1.6, 1.7, 1.75, 1.8, 1.9, 2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.75, 3,
  ]
  private static let intervals: Set<Int> = [5, 10, 15, 30, 45, 60]

  /// Parse from the known field suffix, never by splitting an opaque feed/episode ID on dots.
  public static func parse(key: String, value: String) -> Change? {
    guard !key.isEmpty, key.utf8.count <= 512 else { return nil }
    if key.hasPrefix("listening.") {
      let field = String(key.dropFirst("listening.".count))
      guard shortcutFields.contains(field), allowed(value, field: field, scoped: false) else { return nil }
      return Change(key: key, field: field, scope: .global, value: value)
    }
    guard key.hasPrefix("playback.") else { return nil }
    let rest = String(key.dropFirst("playback.".count))
    for field in playbackFields {
      if rest == field {
        guard allowed(value, field: field, scoped: false) else { return nil }
        return Change(key: key, field: field, scope: .global, value: value)
      }
      guard rest.hasSuffix("." + field) else { continue }
      let scopeText = String(rest.dropLast(field.count + 1))
      let scope: Change.Scope
      if scopeText.hasPrefix("show:") {
        let id = String(scopeText.dropFirst("show:".count))
        guard validID(id) else { return nil }
        scope = .show(id)
      } else if scopeText.hasPrefix("episode:") {
        let id = String(scopeText.dropFirst("episode:".count))
        guard validID(id) else { return nil }
        scope = .episode(id)
      } else { continue }
      guard allowed(value, field: field, scoped: true) else { return nil }
      return Change(key: key, field: field, scope: scope, value: value)
    }
    return nil
  }

  private static func validID(_ id: String) -> Bool {
    !id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && id.utf8.count <= 256
      && !id.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }

  private static func allowed(_ value: String, field: String, scoped: Bool) -> Bool {
    if value.isEmpty { return scoped }
    switch field {
    case "speed": return Double(value).map { speeds.contains($0) } ?? false
    case "backward", "forward": return Int(value).map { intervals.contains($0) } ?? false
    case "doublePress": return ["skipForward", "nextChapter", "mark"].contains(value)
    case "triplePress": return ["skipBack", "sentence", "undoSkipOrSentence", "comment"].contains(value)
    default: return value == "true" || value == "false"
    }
  }

  public static func payload(changes: [String: String], expected: [String: String?], commandID: String)
    throws -> [String: JSONValue]
  {
    let changeJSON = changes.mapValues(JSONValue.string)
    let expectedJSON = expected.mapValues { JSONValue($0) }
    let body: [String: JSONValue] = ["changes": .object(changeJSON), "expected": .object(expectedJSON)]
    guard valid(commandID: commandID, changes: changeJSON, expected: expectedJSON),
      (try Canonical.encode(body)).count <= maximumBodyBytes
    else { throw PlaybackPreferenceBatchError.invalidCommand }
    return body.merging([
      "commandID": .string(commandID),
      "commandDigest": .string(Canonical.digest(try Canonical.encode(body))),
    ]) { _, new in new }
  }

  public static func decode(_ operation: ColophonOperation) -> Body? {
    guard operation.kind == kind, operation.v == 1,
      Set(operation.payload.keys) == ["changes", "expected", "commandID", "commandDigest"],
      let changes = operation.payload["changes"]?.object,
      let expected = operation.payload["expected"]?.object,
      let commandID = operation.payload["commandID"]?.string,
      let claimedDigest = operation.payload["commandDigest"]?.string,
      valid(commandID: commandID, changes: changes, expected: expected)
    else { return nil }
    let body: [String: JSONValue] = ["changes": .object(changes), "expected": .object(expected)]
    guard let canonical = try? Canonical.encode(body), canonical.count <= maximumBodyBytes,
      Canonical.digest(canonical) == claimedDigest
    else { return nil }
    let parsed = changes.compactMap { key, raw -> Change? in
      guard let value = raw.string else { return nil }
      return parse(key: key, value: value)
    }
    guard parsed.count == changes.count else { return nil }
    return Body(commandID: commandID, commandDigest: claimedDigest,
      changes: parsed.sorted { $0.key < $1.key }, expected: expected.mapValues(\.string))
  }

  private static func valid(commandID: String, changes: [String: JSONValue], expected: [String: JSONValue]) -> Bool {
    guard !commandID.isEmpty, commandID.utf8.count <= 128,
      !changes.isEmpty, changes.count <= maximumKeys, changes.keys == expected.keys
    else { return false }
    for (key, raw) in changes {
      guard let value = raw.string, parse(key: key, value: value) != nil else { return false }
      switch expected[key] {
      case .some(.null): break
      case .some(.string(let revision)) where !revision.isEmpty && revision.utf8.count <= 128: break
      default: return false
      }
    }
    return true
  }

  public static func signerKey(_ signer: String, _ commandID: String) -> String {
    "\(signer.utf8.count):\(signer)\(commandID.utf8.count):\(commandID)"
  }

  /// A revision names the immutable per-signer operation path, not just a caller-chosen op ID.
  /// Within one signer, a duplicate clock+ID would address the same create-once store path.
  public static func revision(authorID: String, operation: ColophonOperation) -> String {
    signerKey(authorID, "\(operation.clock):\(operation.id)")
  }
}

public struct PlaybackPreferenceBatchReceipt: Sendable, Equatable {
  public enum Outcome: Sendable, Equatable { case applied, stale }
  public let commandID: String
  public let authorID: String
  public let operationID: String
  public let revision: String
  public let digest: String
  public let outcome: Outcome
  public let changedKeys: [String]
}

public enum PlaybackPreferenceBatchError: Error, Equatable {
  case invalidCommand, noCurrentAccess, wrongRole, commandIDConflict, notAdmitted
}

public struct PlaybackPreferenceBatchService {
  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  /// Authority-only availability for UI capability calculation. This does not promise that a
  /// particular batch passes budget/ceiling caveats or wins an expected-revision comparison.
  public func checkWriter() throws { try requireCurrentWriter() }

  /// The expected map binds the caller's observed per-key revisions (nil for no prior write).
  /// A stale receipt is a local ordered-fold observation, never a distributed CAS guarantee.
  @discardableResult public func commit(changes: [String: String], expected: [String: String?],
    commandID: String) throws -> PlaybackPreferenceBatchReceipt
  {
    let payload = try PlaybackPreferenceBatch.payload(changes: changes, expected: expected, commandID: commandID)
    try checkWriter()
    let state = try replica.state(of: Podcasts.self)
    let key = PlaybackPreferenceBatch.signerKey(replica.identity.id, commandID)
    guard !state.preferenceCommandConflicts.contains(key) else { throw PlaybackPreferenceBatchError.commandIDConflict }
    let digest = payload["commandDigest"]?.string ?? ""
    if let prior = state.preferenceReceipts[key] {
      guard prior.digest == digest else { throw PlaybackPreferenceBatchError.commandIDConflict }
      return prior
    }
    let op = try replica.perform(Command(namespace: Podcasts.namespace, kind: PlaybackPreferenceBatch.kind,
      payload: payload))
    guard let receipt = try replica.state(of: Podcasts.self).preferenceReceipts[key],
      receipt.revision == PlaybackPreferenceBatch.revision(authorID: replica.identity.id, operation: op)
    else { throw PlaybackPreferenceBatchError.notAdmitted }
    return receipt
  }

  private func requireCurrentWriter() throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.revokedAt == nil,
      let grant = member.current, grant.write, grant.namespaces.contains(Podcasts.namespace)
    else { throw PlaybackPreferenceBatchError.noCurrentAccess }
    guard member.role == .app || member.role == .device else { throw PlaybackPreferenceBatchError.wrongRole }
    if let expires = grant.expires, expires < .now { throw PlaybackPreferenceBatchError.noCurrentAccess }
    for caveat in grant.caveats where caveat.namespace == nil || caveat.namespace == Podcasts.namespace {
      switch Caveat.Kind(rawValue: caveat.kind) {
      case .kinds:
        guard caveat.kinds?.contains(PlaybackPreferenceBatch.kind) == true else {
          throw PlaybackPreferenceBatchError.noCurrentAccess
        }
      case .ceiling, .budget:
        // Cumulative admission belongs to Replica's ordered log fold. The receipt below
        // confirms whether this write was actually admitted.
        guard caveat.field != nil, caveat.max != nil else {
          throw PlaybackPreferenceBatchError.noCurrentAccess
        }
      case nil: throw PlaybackPreferenceBatchError.noCurrentAccess
      }
    }
  }
}
