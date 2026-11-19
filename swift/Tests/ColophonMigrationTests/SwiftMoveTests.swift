import Testing
import ColophonSession
@testable import ColophonMigration

struct SwiftMoveTests {
    private func succession(_ stage: MoveStage) -> SwiftSuccession {
        SwiftSuccession(stage: stage, format: "swift/keyring", predecessor: "p", headSeq: 1, headDigest: "d", genesisDigest: "g", handoverCount: 1,
                        authorized: true, vetoed: stage == .vetoed, verifiedSeq: nil, verifiedDigest: nil, timing: nil)
    }
    @Test func eachStageOfTheMoveMapsToTheNextStepAndNothingIsInvented() {
        let expected: [(MoveStage, SwiftMoveNextStep.Action)] = [(.windowNotOpen, .wait), (.waiting, .offerVeto), (.due, .freeze), (.frozen, .copyAndMigrate),
                                                                (.verified, .copyAndMigrate), (.vetoed, .vetoed), (.migrated, .migrated)]
        for (stage, action) in expected { #expect(SwiftMoveNextStep(succession(stage)).action == action, "\(stage)") }
    }
}
