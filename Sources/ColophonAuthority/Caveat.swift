import ColophonCore
import Foundation

/// A condition on a grant beyond namespace and write access (spec §6.4). Every admitting replica
/// evaluates caveats over its own view; a caveat it doesn't recognise denies the operation, so an
/// older client can never be more permissive than a newer one.
public struct Caveat: Codable, Sendable, Hashable {
  public enum Kind: String, Codable, Sendable {
    /// Only these operation kinds.
    case kinds
    /// A numeric payload field may not exceed `max` in any one operation.
    case ceiling
    /// The sum of a numeric payload field across this member's admitted operations in the
    /// namespace may not exceed `max`.
    case budget
  }

  /// Raw kind, so unknown kinds survive decoding and can be refused.
  public let kind: String
  public var namespace: String?
  public var kinds: [String]?
  public var field: String?
  /// Integer, in the field's unit (for money: minor units such as US cents).
  public var max: Int?

  public init(kind: String, namespace: String? = nil, kinds: [String]? = nil, field: String? = nil, max: Int? = nil) {
    self.kind = kind
    self.namespace = namespace
    self.kinds = kinds
    self.field = field
    self.max = max
  }

  public static func only(_ kinds: [String], in namespace: String) -> Caveat {
    Caveat(kind: Kind.kinds.rawValue, namespace: namespace, kinds: kinds)
  }

  public static func ceiling(_ field: String, max: Int, in namespace: String) -> Caveat {
    Caveat(kind: Kind.ceiling.rawValue, namespace: namespace, field: field, max: max)
  }

  public static func budget(_ field: String, max: Int, in namespace: String) -> Caveat {
    Caveat(kind: Kind.budget.rawValue, namespace: namespace, field: field, max: max)
  }
}
