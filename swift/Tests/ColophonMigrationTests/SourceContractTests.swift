import Foundation
import Testing
@testable import ColophonMigration

struct SourceContractTests {
    @Test func fingerprintDetectsAdmissionAndSemanticChanges() {
        func operation(_ admission: LegacyAdmission, _ semantic: String) -> LegacyOperation {
            .init(id: "op", authorID: "member", authorLabel: "App", signedBodyDigest: String(repeating: "a", count: 64),
                  kind: "book.add", version: 1, payloadJSON: Data("{}".utf8), claimedDateJSON: Data("null".utf8),
                  admission: admission, sourcePath: "ops/member/op.json", semanticFingerprint: semantic)
        }
        let admitted = operation(.admitted, "receipt-1")
        #expect(admitted.key == operation(.held, "receipt-1").key)
        #expect(admitted.fingerprint != operation(.held, "receipt-1").fingerprint)
        #expect(admitted.fingerprint != operation(.admitted, "receipt-2").fingerprint)
    }
}
