import ColophonCore
import Foundation

/// A read-only question a module answers from what a member can see (spec §9.3), such as an
/// episode's transcript. Adapters expose queries beside operations, so an agent asks the same
/// things the app's own features do.
public struct QuerySpec: Sendable {
  public let name: String
  public let summary: String
  public let fields: [FieldSpec]
  public let run: @Sendable (Replica, [String: JSONValue]) throws -> JSONValue

  public init(_ name: String, _ summary: String, _ fields: [FieldSpec],
    run: @escaping @Sendable (Replica, [String: JSONValue]) throws -> JSONValue)
  {
    self.name = name
    self.summary = summary
    self.fields = fields
    self.run = run
  }
}

public extension DomainModule {
  static var queries: [QuerySpec] { [] }
}
