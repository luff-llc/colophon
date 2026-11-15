import Foundation
import Testing
import ColophonSession

@MainActor struct PairingTests {
    private struct Ceremony { let key: PairingTransferKey; let joiner: AccountPairing; let existing: AccountPairing }

    /// The pairing ceremony of spec §7.3 through the exports: both screens show one six-digit code.
    private func ceremony(account: String) throws -> Ceremony {
        let key = try PairingTransferKey.create(entropy: try colophonEntropy(32))
        let joiner = try AccountPairing.join(account: account, e: try key.public(), nb: try colophonEntropy(32))
        let limiter = try PairingFailureLimiter.fromState(state: "")
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let existing = try AccountPairing.existingReceiveCommitment(account: account, commitment: try joiner.commitment(), limiter: limiter, nowMs: now)
        let nonce = try existing.sendNonce(na: try colophonEntropy(32))
        let reveal = try #require(try joiner.receiveNonce(na: nonce))
        let shown = try existing.receiveReveal(e: reveal.e, nb: reveal.nb, limiter: limiter, nowMs: now)
        #expect(shown == (try joiner.digits()), "both screens show the same code")
        try existing.confirm(); try joiner.confirm()
        return Ceremony(key: key, joiner: joiner, existing: existing)
    }

    /// The first device adds the laptop's owner key as a controller. The laptop gets the seed by pairing, builds its own
    /// slot, and from then on unlocks alone: it approves its own device's request as the owner.
    @Test func aSecondDeviceJoinsByPairingAndSeedTransferAndThenActsAsOwner() async throws {
        let first = Device()
        await first.session.create()
        let laptopOwner = SoftwareKeys()
        try await first.session.addController(laptopOwner, label: "Laptop", roles: [.approve], immediate: true)
        let account = try #require(first.session.libraryID)

        let second = Device(medium: first.medium.copy(), owner: laptopOwner)
        await second.session.restore()
        guard case .waitingForApproval = second.session.phase else { Issue.record("expected waiting, got \(second.session.phase)"); return }
        let c = try ceremony(account: account)
        let sealed = try await first.session.transferSeed(pairing: c.existing)
        try await second.session.acceptSeedTransfer(key: c.key, pairing: c.joiner, sealed: sealed, label: "Laptop")
        #expect(second.medium.snapshot().count > first.medium.snapshot().count - 1, "the laptop stored its own slot entry")
        // It now unlocks alone: approve this device's own request with the laptop's owner key.
        await second.session.refresh()
        let raw = try await second.session.exportRequest()
        let info = try accountRequestInfo(raw: raw)
        try await second.session.approve(AccessRequest(id: info.member, label: info.label, kind: info.kind, termsJSON: info.termsJson, record: raw))
        await second.session.refresh()
        #expect(second.session.phase == .ready, "\(second.session.phase)")
    }

    @Test func aSeedSealedToAnotherPairingIsRefusedAndLeavesTheDeviceLocked() async throws {
        let first = Device()
        await first.session.create()
        let laptopOwner = SoftwareKeys()
        try await first.session.addController(laptopOwner, label: "Laptop", roles: [.approve], immediate: true)
        let account = try #require(first.session.libraryID)
        let second = Device(medium: first.medium.copy(), owner: laptopOwner)
        await second.session.restore()
        let real = try ceremony(account: account)
        let other = try ceremony(account: account)
        let sealed = try await first.session.transferSeed(pairing: real.existing)
        let before = second.medium.snapshot().count
        await #expect(throws: ColophonError.self) {
            try await second.session.acceptSeedTransfer(key: other.key, pairing: other.joiner, sealed: sealed, label: "Laptop")
        }
        #expect(second.medium.snapshot().count == before, "nothing was stored")
        // A device that never got the seed cannot act as owner: the owner key has no slot to open.
        await #expect(throws: (any Error).self) { try await second.session.approve(AccessRequest(id: "0", label: "x", kind: .app, termsJSON: "{}", record: Data())) }
    }
}
