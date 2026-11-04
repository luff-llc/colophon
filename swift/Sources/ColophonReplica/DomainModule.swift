import ColophonCore
import Foundation

/// A change a client asks for, before it's sealed and signed.
public struct Command: Sendable, Equatable {
  public let namespace: String
  public let kind: String
  public let v: Int
  public let payload: [String: JSONValue]

  public init(namespace: String, kind: String, v: Int = 1, payload: [String: JSONValue]) {
    self.namespace = namespace
    self.kind = kind
    self.v = v
    self.payload = payload
  }
}

/// A domain: a namespace, its operation vocabulary and how operations fold into state (spec §9).
/// Apps, the MCP adapter and App Intents all speak to a library through modules, so a person's
/// data means the same thing in every client.
public protocol DomainModule: Sendable {
  associatedtype State: Sendable
  static var namespace: String { get }
  static var version: Int { get }
  /// Operation kinds this version understands.
  static var kinds: [String] { get }
  /// Folds admitted operations, already in the agreed order, into state. Must be deterministic
  /// and must skip kinds it doesn't know rather than fail.
  static func fold(_ view: ReplicaView) -> State
  /// The operations adapters may offer, with their fields. Optional.
  static var operations: [OperationSpec] { get }
  /// Domain-specific shape validation shared by generated writers. Folds still validate received records.
  static func validate(_ kind: String, _ payload: [String: JSONValue]) throws
  /// A JSON summary of state for adapters such as MCP. Optional.
  static func describe(_ state: State) -> JSONValue
  /// Read-only questions adapters may offer. Optional.
  static var queries: [QuerySpec] { get }
}

public extension DomainModule {
  static func command(_ kind: String, _ payload: [String: JSONValue]) -> Command {
    Command(namespace: namespace, kind: kind, v: version, payload: payload)
  }
}

/// What one member can see of one namespace.
public struct ReplicaView: Sendable {
  /// Authenticated authority context. A manually built view may omit it, but an import
  /// projection then fails closed instead of trusting a payload's claimed library ID.
  public let libraryID: String?
  /// Requested/verified scope supplied by Replica. Nil on manual views without provenance.
  /// This is context, not authentication of caller-manufactured ReplicaView values.
  public let namespace: String?
  public let operations: [AdmittedOperation]
  public let rejected: [RejectedOperation]
  /// Operations sealed under an epoch this member never received.
  public let unreadable: Int

  public init(operations: [AdmittedOperation], rejected: [RejectedOperation], unreadable: Int,
    libraryID: String? = nil, namespace: String? = nil)
  {
    self.libraryID = libraryID; self.namespace = namespace
    self.operations = operations
    self.rejected = rejected
    self.unreadable = unreadable
  }

  public var admitted: [AdmittedOperation] { operations.filter { $0.status == .admitted } }
  public var held: [AdmittedOperation] { operations.filter { $0.status != .admitted } }
}
