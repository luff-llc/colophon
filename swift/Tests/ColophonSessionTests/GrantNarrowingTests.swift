import Foundation
import Testing
import ColophonKit
@testable import ColophonSession

/// A grant narrows the request's own terms (spec §9.1): fields left nil keep the request's, per-namespace access and
/// everything else in the request (kinds, services) survive. Before 0.5.0's final commit the Swift session rebuilt the
/// terms from scratch, widening a mixed request's read namespace to write and dropping kinds, so the core refused the
/// grant after spending the pairing.
struct GrantNarrowingTests {
    private func object(_ json: String) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    }
    private let request = #"{"records":[{"access":"read","namespace":"listening.podcasts"},{"access":"write","kinds":["note.put"],"namespace":"notes"}],"services":[{"purposes":["a.b"]}]}"#

    @Test func aBudgetOnlyGrantKeepsEachNamespacesAccessAndTheRest() throws {
        let terms = try object(SessionWorker.narrowed(requestTerms: request, options: GrantOptions(namespaces: nil, access: nil, expires: nil, writeBudget: 5)))
        let records = try #require(terms["records"] as? [[String: Any]])
        #expect(records.map { $0["access"] as? String } == ["read", "write"])
        #expect(records[1]["kinds"] as? [String] == ["note.put"])
        #expect(terms["services"] != nil)
        #expect(terms["writes"] as? Int == 5)
    }

    @Test func namespacesAndReadOnlyNarrow() throws {
        let terms = try object(SessionWorker.narrowed(requestTerms: request, options: GrantOptions(namespaces: ["notes"], access: [.read], expires: "2027-01-01T00:00:00Z", writeBudget: nil)))
        let records = try #require(terms["records"] as? [[String: Any]])
        #expect(records.count == 1)
        #expect(records[0]["namespace"] as? String == "notes" && records[0]["access"] as? String == "read")
        #expect(records[0]["kinds"] as? [String] == ["note.put"])
        #expect(terms["expires"] as? String == "2027-01-01T00:00:00Z")
    }
}
