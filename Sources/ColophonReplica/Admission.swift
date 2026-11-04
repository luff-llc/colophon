import ColophonAuthority
import ColophonCore
import Foundation

/// The admission rule (spec §8.3), applied to operations in their agreed order.
///
/// A signature shows only who wrote something. Whether it counts depends on the grant in force at
/// the authority entry the author cites, that grant's caveats, and whether the author was later
/// revoked.
struct Admission {
  struct Refusal: Error { let message: String }

  let state: AuthorityState
  let namespace: String
  /// Running totals for `budget` caveats: member ID → field → sum so far.
  private var spent: [String: [String: Int]] = [:]

  init(state: AuthorityState, namespace: String) {
    self.state = state
    self.namespace = namespace
  }

  mutating func judge(_ operation: ColophonOperation, header: OperationHeader, author: AuthorityState.Member)
    -> Result<AdmittedOperation.Status, Refusal>
  {
    if operation.authority > state.latest {
      return .success(.held("Cites authority this copy hasn't received yet"))
    }
    guard let grant = author.grant(at: operation.authority) else { return .failure(Refusal(message: "Written before the grant")) }
    guard grant.write, grant.namespaces.contains(namespace) else {
      return .failure(Refusal(message: "No write grant for \(namespace)"))
    }
    guard state.epoch(of: namespace, at: operation.authority) == header.epoch else {
      return .failure(Refusal(message: "Sealed with the wrong key epoch"))
    }
    // Expiry binds honest writers only: `created` is the author's own clock.
    if let expires = grant.expires, operation.created > expires {
      return .failure(Refusal(message: "Written after the grant expired"))
    }
    if let revoked = author.revokedAt, !author.kept.contains(operation.id) {
      // Citing the revocation or later is refused. Citing earlier history may be honest offline
      // work or a backdated forgery; nothing in the record can tell which, so it waits for a person.
      return operation.authority >= revoked
        ? .failure(Refusal(message: "Written after access was revoked"))
        : .success(.held("Written by a member whose access was later revoked"))
    }
    if let refusal = check(grant.caveats, operation, author: author.id) { return .failure(refusal) }
    return .success(.admitted)
  }

  /// Caveats fail closed: a kind this replica doesn't know refuses the operation.
  private mutating func check(_ caveats: [Caveat], _ operation: ColophonOperation, author: String) -> Refusal? {
    // The listening module depends on Replica, so this admission layer cannot import its
    // decoder. This stable wire-kind fence ensures malformed natural-end cost claims cannot
    // credit a cumulative budget before that module rejects the signed operation. Generic
    // negative amounts remain valid for other kinds whose contracts support refunds.
    if namespace == "listening.podcasts", operation.kind == "playback.naturalEnd.batch" {
      guard let seconds = Self.amount(operation.payload["seconds"]), seconds > 0,
        let duration = Self.amount(operation.payload["duration"]), duration > 0 else {
        return Refusal(message: "Invalid natural-end costs")
      }
    }
    var pending: [(field: String, amount: Int)] = []
    for caveat in caveats where caveat.namespace == nil || caveat.namespace == namespace {
      switch Caveat.Kind(rawValue: caveat.kind) {
      case .kinds:
        guard caveat.kinds?.contains(operation.kind) == true else {
          return Refusal(message: "The grant doesn't allow \(operation.kind)")
        }
      case .ceiling:
        guard let field = caveat.field, let max = caveat.max else { return Refusal(message: "Malformed ceiling caveat") }
        if let amount = Self.amount(operation.payload[field]), amount > max {
          return Refusal(message: "\(field) exceeds the grant's ceiling")
        }
      case .budget:
        guard let field = caveat.field, let max = caveat.max else { return Refusal(message: "Malformed budget caveat") }
        if let amount = Self.amount(operation.payload[field]) {
          guard (spent[author]?[field] ?? 0) + amount <= max else {
            return Refusal(message: "\(field) would exceed the grant's budget")
          }
          pending.append((field, amount))
        }
      case nil:
        return Refusal(message: "The grant has a condition this app doesn't understand")
      }
    }
    for (field, amount) in pending { spent[author, default: [:]][field, default: 0] += amount }
    return nil
  }

  /// Amounts are integers in minor units. Anything else doesn't count as an amount.
  private static func amount(_ value: JSONValue?) -> Int? {
    guard case .number(let number) = value, number.rounded() == number, abs(number) < 1e15 else { return nil }
    return Int(number)
  }
}
