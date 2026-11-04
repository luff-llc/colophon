import ColophonCore
import Foundation

/// A machine-readable description of one operation kind (spec §9.2). Adapters — MCP tools, App
/// Intents, command lines, HTTP — are generated from these, so every surface accepts the same
/// operations with the same fields.
public struct OperationSpec: Sendable {
  public let kind: String
  public let summary: String
  public let fields: [FieldSpec]

  public init(_ kind: String, _ summary: String, _ fields: [FieldSpec]) {
    self.kind = kind
    self.summary = summary
    self.fields = fields
  }

  /// Checks types and required fields, and drops nothing: unknown fields pass through.
  public func validate(_ payload: [String: JSONValue]) throws {
    for field in fields {
      guard let value = payload[field.name], value != .null else {
        if field.required { throw ColophonError.malformed("\(kind): missing \(field.name)") }
        continue
      }
      guard field.type.accepts(value) else { throw ColophonError.malformed("\(kind): \(field.name) should be \(field.type)") }
      if let allowed = field.values, let string = value.string, !allowed.contains(string) {
        throw ColophonError.malformed("\(kind): \(field.name) must be one of \(allowed.joined(separator: ", "))")
      }
    }
  }
}

public struct FieldSpec: Sendable {
  public enum FieldType: String, Sendable {
    case string, number, integer, boolean, strings, object
    /// A list of objects, such as chapter entries or ad segments.
    case objects

    func accepts(_ value: JSONValue) -> Bool {
      switch self {
      case .string: value.string != nil
      case .number: value.double != nil
      case .integer: value.int != nil
      case .boolean: value.bool != nil
      case .strings: value.array?.allSatisfy { $0.string != nil } == true
      case .object: value.object != nil
      case .objects: value.array?.allSatisfy { $0.object != nil } == true
      }
    }
  }

  public let name: String
  public let type: FieldType
  public let required: Bool
  public let summary: String
  public let values: [String]?

  public init(_ name: String, _ type: FieldType, required: Bool = false, _ summary: String, values: [String]? = nil) {
    self.name = name
    self.type = type
    self.required = required
    self.summary = summary
    self.values = values
  }

  /// JSON Schema for this field.
  public var schema: JSONValue {
    var object: [String: JSONValue] = ["description": .string(summary)]
    switch type {
    case .strings: object["type"] = "array"; object["items"] = .object(["type": "string"])
    case .object: object["type"] = "object"
    case .objects: object["type"] = "array"; object["items"] = .object(["type": "object"])
    default: object["type"] = .string(type.rawValue)
    }
    if let values { object["enum"] = .array(values.map(JSONValue.string)) }
    return .object(object)
  }
}

extension JSONValue: ExpressibleByStringLiteral {
  public init(stringLiteral value: String) { self = .string(value) }
}

public extension DomainModule {
  static var operations: [OperationSpec] { [] }
  static func describe(_ state: State) -> JSONValue { .null }

  /// Builds a command after checking it against this module's spec for that kind.
  static func validated(_ kind: String, _ payload: [String: JSONValue]) throws -> Command {
    try validate(kind, payload)
    return command(kind, payload)
  }

  static func validate(_ kind: String, _ payload: [String: JSONValue]) throws {
    guard let spec = operations.first(where: { $0.kind == kind }) else {
      throw ColophonError.malformed("\(namespace) has no operation \(kind)")
    }
    try spec.validate(payload)
  }
}
