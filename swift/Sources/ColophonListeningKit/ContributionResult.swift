import Foundation
import ColophonSession

/// The contributions query returns one full record when id is supplied, otherwise a page.
public enum ContributionResult: Codable, Equatable, Sendable {
    case page(DomainPage<ContributionRow>), detail(ContributionDetail)
    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let page = try? c.decode(DomainPage<ContributionRow>.self) { self = .page(page) }
        else { self = .detail(try c.decode(ContributionDetail.self)) }
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self { case .page(let v): try c.encode(v); case .detail(let v): try c.encode(v) }
    }
}
