import ColophonCore
import ColophonReplica
import Foundation

/// An MCP server over a replica (spec §10). It is an adapter only: every tool reads through the
/// replica's keys and writes as the replica's member, so an agent gets exactly that member's grant
/// and its writes are attributed to it.
///
/// Transport is the caller's: feed it JSON-RPC messages from stdio, HTTP or a sealed relay.
public struct MCPServer: Sendable {
  public let replica: Replica
  public let modules: [ModuleAdapter]
  public let name: String

  public init(replica: Replica, modules: [ModuleAdapter], name: String = "colophon") {
    self.replica = replica
    self.modules = modules
    self.name = name
  }

  /// Handles one JSON-RPC message. Returns nil for notifications.
  public func handle(_ message: Data) -> Data? {
    guard let request = try? JSONDecoder().decode([String: JSONValue].self, from: message),
      let method = request["method"]?.string
    else { return encode(["jsonrpc": "2.0", "id": .null, "error": error(-32700, "Parse error")]) }
    guard let id = request["id"] else { return nil }
    let params = request["params"]?.object ?? [:]
    let result: JSONValue
    switch method {
    case "initialize":
      result = .object(["protocolVersion": .string(params["protocolVersion"]?.string ?? "2025-06-18"),
        "capabilities": .object(["tools": .object([:])]), "serverInfo": .object(["name": .string(name), "version": "0.1"])])
    case "ping":
      result = .object([:])
    case "tools/list":
      result = .object(["tools": .array(tools)])
    case "tools/call":
      result = call(params["name"]?.string ?? "", params["arguments"]?.object ?? [:])
    default:
      return encode(["jsonrpc": "2.0", "id": id, "error": error(-32601, "Method not found")])
    }
    return encode(["jsonrpc": "2.0", "id": id, "result": result])
  }

  var tools: [JSONValue] {
    var list: [JSONValue] = [tool("library__status", "Who this agent is in the library and what it may do.", [])]
    for module in modules {
      list.append(tool(module.readTool, "Read \(module.namespace).", []))
      for operation in module.operations {
        list.append(tool(ModuleAdapter.toolName(module.namespace, operation.kind), operation.summary, operation.fields))
      }
      for query in module.queries {
        list.append(tool(ModuleAdapter.toolName(module.namespace, query.name), query.summary, query.fields))
      }
    }
    return list
  }

  private func tool(_ name: String, _ description: String, _ fields: [FieldSpec]) -> JSONValue {
    .object(["name": .string(name), "description": .string(description), "inputSchema": .object([
      "type": "object",
      "properties": .object(Dictionary(uniqueKeysWithValues: fields.map { ($0.name, $0.schema) })),
      "required": .array(fields.filter(\.required).map { .string($0.name) }),
    ])])
  }

  private func call(_ name: String, _ arguments: [String: JSONValue]) -> JSONValue {
    do {
      if name == "library__status" { return text(try status()) }
      for module in modules {
        if name == module.readTool { return text(try module.describe(replica)) }
        if let query = module.queries.first(where: { ModuleAdapter.toolName(module.namespace, $0.name) == name }) {
          for field in query.fields where field.required && arguments[field.name] == nil {
            return failure("Missing \(field.name)")
          }
          return text(try query.run(replica, arguments))
        }
        if let operation = module.operations.first(where: { ModuleAdapter.toolName(module.namespace, $0.kind) == name }) {
          let written = try replica.perform(module.command(operation.kind, arguments))
          return text(.object(["operation": .string(written.id), "status": "written"]))
        }
      }
      return failure("Unknown tool \(name)")
    } catch {
      return failure(error.localizedDescription)
    }
  }

  private func status() throws -> JSONValue {
    let state = try replica.authority()
    let member = state.members[replica.identity.id]
    let grant = member?.current
    return .object(["library": .string(state.label), "member": JSONValue(member?.label),
      "namespaces": .array((grant?.namespaces ?? []).map(JSONValue.string)), "write": .bool(grant?.write ?? false),
      "revoked": .bool(member?.revokedAt != nil)])
  }

  private func text(_ value: JSONValue) -> JSONValue {
    let data = (try? Canonical.encode(value)) ?? Data()
    return .object(["content": .array([.object(["type": "text", "text": .string(String(decoding: data, as: UTF8.self))])])])
  }

  private func failure(_ message: String) -> JSONValue {
    .object(["isError": .bool(true), "content": .array([.object(["type": "text", "text": .string(message)])])])
  }

  private func error(_ code: Int, _ message: String) -> JSONValue {
    .object(["code": .number(Double(code)), "message": .string(message)])
  }

  private func encode(_ object: [String: JSONValue]) -> Data? { try? Canonical.encode(object) }
}
