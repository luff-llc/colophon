import ColophonCore
import ColophonReplica
import Foundation

/// A domain module with its types erased, so one server can host any mix of modules.
public struct ModuleAdapter: Sendable {
  public let namespace: String
  public let operations: [OperationSpec]
  public let queries: [QuerySpec]
  let describe: @Sendable (Replica) throws -> JSONValue
  let command: @Sendable (String, [String: JSONValue]) throws -> Command

  public init<M: DomainModule>(_ module: M.Type) {
    namespace = M.namespace
    operations = M.operations
    queries = M.queries
    describe = { replica in M.describe(try replica.state(of: M.self)) }
    command = { kind, payload in try M.validated(kind, payload) }
  }

  /// Tool names are `<namespace>__<kind>` with dots as underscores, within MCP's character set.
  static func toolName(_ namespace: String, _ suffix: String) -> String {
    (namespace + "__" + suffix).replacingOccurrences(of: ".", with: "_")
  }

  var readTool: String { Self.toolName(namespace, "read") }
}
