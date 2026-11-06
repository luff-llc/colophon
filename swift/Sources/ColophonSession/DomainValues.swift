import Foundation

/// JSON reserved for extension bags and fields whose domain contract explicitly permits JSON.
public enum DomainJSON: Codable, Hashable, Sendable {
    case null, bool(Bool), number(Double), string(String), array([DomainJSON]), object([String: DomainJSON])

    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode([DomainJSON].self) { self = .array(v) }
        else { self = .object(try c.decode([String: DomainJSON].self)) }
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }
}

/// Use nil for omission, .null to clear/expect no head, and .value for a supplied value.
/// In particular, Optional<String> alone cannot express all three command meanings.
public enum DomainNullable<Value: Codable & Hashable & Sendable>: Codable, Hashable, Sendable {
    case null, value(Value)
    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        self = c.decodeNil() ? .null : .value(try c.decode(Value.self))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self { case .null: try c.encodeNil(); case .value(let v): try c.encode(v) }
    }
}

/// Dynamic coding keys preserve unknown command/model fields when round-tripping.
public struct DomainCodingKey: CodingKey {
    public let stringValue: String
    public var intValue: Int? { nil }
    public init(_ value: String) { stringValue = value }
    public init?(stringValue: String) { self.init(stringValue) }
    public init?(intValue: Int) { return nil }
}

public protocol TypedDomainCommand: Codable, Hashable, Sendable {
    static var namespace: String { get }
    static var kind: String { get }
}
extension TypedDomainCommand {
    public func domainCommand() throws -> DomainCommand {
        try DomainCommand(namespace: Self.namespace, kind: Self.kind, payload: self)
    }
}

public struct DomainPage<Row: Codable & Equatable & Sendable>: Codable, Equatable, Sendable {
    public let rows: [Row]
    public let next: String?
    public let total: Int
    public init(rows: [Row], next: String?, total: Int) {
        self.rows = rows; self.next = next; self.total = total
    }
}

/// Expected domain outcomes stay distinct from an empty page and from transport failures.
public enum DomainQueryFailure: String, Codable, Error, Sendable {
    case notFound, deleted, notGranted, unavailable, invalidArgument, staleCursor, contentTooLarge
}

public enum DomainQueryResult<Value: Codable & Equatable & Sendable>: Codable, Equatable, Sendable {
    case success(revision: String, value: Value)
    case failure(DomainQueryFailure)
    public var value: Value? { if case .success(_, let value) = self { value } else { nil } }
    public var revision: String? { if case .success(let revision, _) = self { revision } else { nil } }
    public func get() throws -> Value {
        switch self { case .success(_, let value): value; case .failure(let reason): throw reason }
    }
    private enum Keys: String, CodingKey { case revision, value, outcome, ok, reason }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        if let outcome = try c.decodeIfPresent(DomainQueryFailure.self, forKey: .outcome) {
            self = .failure(outcome); return
        }
        if try c.decodeIfPresent(Bool.self, forKey: .ok) == false {
            self = .failure(try c.decode(DomainQueryFailure.self, forKey: .reason)); return
        }
        if let nested = try? c.nestedContainer(keyedBy: Keys.self, forKey: .value) {
            if let outcome = try nested.decodeIfPresent(DomainQueryFailure.self, forKey: .outcome) {
                self = .failure(outcome); return
            }
            if try nested.decodeIfPresent(Bool.self, forKey: .ok) == false {
                self = .failure(try nested.decode(DomainQueryFailure.self, forKey: .reason)); return
            }
        }
        self = .success(revision: try c.decode(String.self, forKey: .revision),
                        value: try c.decode(Value.self, forKey: .value))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Keys.self)
        switch self {
        case .success(let revision, let value):
            try c.encode(revision, forKey: .revision); try c.encode(value, forKey: .value)
        case .failure(let reason): try c.encode(reason, forKey: .outcome)
        }
    }
}

public protocol TypedDomainQuery: Codable, Hashable, Sendable {
    associatedtype Value: Codable & Equatable & Sendable
    static var namespace: String { get }
    static var name: String { get }
}
public protocol PagedDomainQuery: TypedDomainQuery {
    var cursor: String? { get set }
}
extension PagedDomainQuery {
    /// Keeps the exact filters. A stale cursor must be explicitly restarted, never appended.
    public func page(after cursor: String?) -> Self { var copy = self; copy.cursor = cursor; return copy }
    public func nextPage<Row>(after page: DomainPage<Row>) -> Self? {
        page.next.map { self.page(after: $0) }
    }
    public func firstPage() -> Self { page(after: nil) }
}

/// Bounded heterogeneous query cache key; the result decoder runs off the main actor.
public struct DomainQueryKey: Hashable, Sendable {
    public let namespace: String
    public let name: String
    public let arguments: Data
    private let resultType: ObjectIdentifier
    private let decode: @Sendable (Data) throws -> any Sendable
    public init<Q: TypedDomainQuery>(_ query: Q) throws {
        namespace = Q.namespace; name = Q.name
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        arguments = try encoder.encode(query)
        resultType = ObjectIdentifier(Q.Value.self)
        decode = { try JSONDecoder().decode(DomainQueryResult<Q.Value>.self, from: $0) }
    }
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.namespace == rhs.namespace && lhs.name == rhs.name && lhs.arguments == rhs.arguments && lhs.resultType == rhs.resultType
    }
    public func hash(into hasher: inout Hasher) {
        hasher.combine(namespace); hasher.combine(name); hasher.combine(arguments); hasher.combine(resultType)
    }
    @concurrent public func evaluate(session: ColophonSession) async throws -> any Sendable {
        let bytes = try await session.query(namespace: namespace, name: name, arguments: arguments)
        try Task.checkCancellation()
        return try decode(bytes)
    }
}
