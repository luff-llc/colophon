import Foundation

/// Any JSON value. Operation payloads use it so a client keeps fields it does not understand
/// instead of dropping them when it reads or rewrites a record.
public enum JSONValue: Codable, Hashable, Sendable {
  case null, bool(Bool), number(Double), string(String), array([JSONValue]), object([String: JSONValue])

  public init(from decoder: any Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() { self = .null }
    else if let value = try? container.decode(Bool.self) { self = .bool(value) }
    else if let value = try? container.decode(Double.self) { self = .number(value) }
    else if let value = try? container.decode(String.self) { self = .string(value) }
    else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
    else { self = .object(try container.decode([String: JSONValue].self)) }
  }

  public func encode(to encoder: any Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .null: try container.encodeNil()
    case .bool(let value): try container.encode(value)
    case .number(let value): try container.encode(value)
    case .string(let value): try container.encode(value)
    case .array(let value): try container.encode(value)
    case .object(let value): try container.encode(value)
    }
  }

  public var string: String? { if case .string(let value) = self { value } else { nil } }
  public var double: Double? { if case .number(let value) = self { value } else { nil } }
  public var int: Int? { double.flatMap { $0.rounded() == $0 && abs($0) < 1e15 ? Int($0) : nil } }
  public var bool: Bool? { if case .bool(let value) = self { value } else { nil } }
  public var array: [JSONValue]? { if case .array(let value) = self { value } else { nil } }
  public var object: [String: JSONValue]? { if case .object(let value) = self { value } else { nil } }

  public init(_ value: String?) { self = value.map(JSONValue.string) ?? .null }
  public init(_ value: Double?) { self = value.map(JSONValue.number) ?? .null }
  public init(_ value: Int?) { self = value.map { .number(Double($0)) } ?? .null }
  public init(_ value: Bool?) { self = value.map(JSONValue.bool) ?? .null }
}
