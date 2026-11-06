import Foundation

/// The core's deterministic (clock, author, operation) key, not a wall-clock date.
public struct FoldOrder: Codable, Equatable, Sendable {
    public let clock: Int
    public let author: String
    public let operation: String
    public init(clock: Int, author: String, operation: String) {
        self.clock = clock; self.author = author; self.operation = operation
    }
    public init(from decoder: any Decoder) throws {
        var c = try decoder.unkeyedContainer()
        clock = try c.decode(Int.self); author = try c.decode(String.self); operation = try c.decode(String.self)
        guard c.isAtEnd else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "Expected fold-order triple") }
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.unkeyedContainer()
        try c.encode(clock); try c.encode(author); try c.encode(operation)
    }
}
