import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
import ColophonSession

/// A session whose `libraryNamespaces` (what the account declares at genesis) is wider than its own `namespaces` (what
/// its member is granted) is ready after `create()`: readiness and published revisions follow the member's own
/// namespaces, not the library's. Before 0.5.0's final commit it came out `denied`.
@MainActor struct LibraryNamespacesTests {
    static let all = ["listening.podcasts", "notes", "reading.books", "reading.saved"]

    private func created(_ namespaces: [String], library: [String], home: SimHome? = nil) async -> Device {
        var homes: [HomeConfiguration] = []
        if let home {
            let make: @Sendable (String) async throws -> Data = { account in
                home.setAccount(account)
                return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
            }
            homes = [HomeConfiguration(endpoint: URL(string: home.base + "/")!, label: "Home", request: make, transport: home)]
        }
        let device = Device(homes: homes, createWithoutHome: home == nil, namespaces: namespaces, libraryNamespaces: library)
        await device.session.create()
        return device
    }

    @Test(arguments: [false, true])
    func oneOwnNamespaceOfAllFourIsReady(withHome: Bool) async throws {
        let device = await created(["listening.podcasts"], library: Self.all, home: withHome ? SimHome() : nil)
        #expect(device.session.phase == .ready, "\(device.session.phase)")
        #expect(device.session.members.contains { $0.grant?.namespaces == ["listening.podcasts"] })
    }

    @Test(arguments: [false, true])
    func aNarrowerMemberThanTheLibraryIsReady(withHome: Bool) async throws {
        let device = await created(["reading.saved"], library: ["reading.saved", "notes"], home: withHome ? SimHome() : nil)
        #expect(device.session.phase == .ready, "\(device.session.phase)")
    }

    @Test(arguments: [false, true])
    func equalListsAreReady(withHome: Bool) async throws {
        let device = await created(["reading.saved", "notes"], library: ["reading.saved", "notes"], home: withHome ? SimHome() : nil)
        #expect(device.session.phase == .ready, "\(device.session.phase)")
    }
}

/// The owner's engine sees every namespace of the account, whatever the app's own `libraryNamespaces`: a revoke made from
/// an app whose library is narrower keeps what the revoked member wrote in the other namespaces. Before 0.5.0's final
/// commit the owner engine was scoped to the app's library, and the revoked member's saved items were dropped.
@MainActor struct OwnerScopeTests {
    @Test func aRevokeFromANarrowerAppKeepsWhatTheMemberWroteElsewhere() async throws {
        let all = ["notes", "reading.saved"]
        let writer = Device(namespaces: ["reading.saved"], libraryNamespaces: all)
        let notes = Device(medium: writer.medium, owner: writer.owner, namespaces: ["notes"])
        let reader = Device(medium: writer.medium, owner: writer.owner, namespaces: ["reading.saved"], libraryNamespaces: all)
        await writer.session.create()
        #expect(writer.session.phase == .ready, "\(writer.session.phase)")
        try await writer.session.perform(try .saveLink(id: "kept", url: URL(string: "https://example.org/kept")!, title: "Kept"), observed: writer.session.observedRevision)
        await notes.session.restore(); try await approveByScan(joining: notes.session, approving: writer.session); await notes.session.refresh()
        #expect(notes.session.phase == .ready, "\(notes.session.phase)")
        await reader.session.restore(); try await approveByScan(joining: reader.session, approving: writer.session); await reader.session.refresh()
        #expect(reader.session.phase == .ready, "\(reader.session.phase)")
        #expect(try await SavedStore(session: reader.session).load(ItemsQuery(limit: 10)).get().total == 1)
        // The notes app, whose library is only notes, revokes the writer.
        try await notes.session.revoke(memberID: try #require(writer.session.memberID))
        await reader.session.refresh()
        #expect(reader.session.phase == .ready, "\(reader.session.phase)")
        #expect(try await SavedStore(session: reader.session).load(ItemsQuery(limit: 10)).get().total == 1, "the revoked member's item is kept")
    }
}

/// `GrantOptions` fields left nil inherit the request, not the approving app's own namespaces.
@MainActor struct GrantInheritanceTests {
    @Test func aGrantWithOnlyABudgetKeepsTheRequestsNamespaces() async throws {
        let approver = Device(namespaces: ["reading.saved"], libraryNamespaces: ["notes", "reading.saved"])
        let joining = Device(medium: approver.medium, owner: approver.owner, namespaces: ["notes"], libraryNamespaces: ["notes", "reading.saved"])
        await approver.session.create()
        await joining.session.restore()
        try await approveByScan(joining: joining.session, approving: approver.session,
                                grant: GrantOptions(namespaces: nil, access: nil, expires: nil, writeBudget: 100))
        await joining.session.refresh()
        #expect(joining.session.phase == .ready, "\(joining.session.phase)")
        let member = try #require(approver.session.members.first { $0.id == joining.session.memberID })
        #expect(member.grant?.namespaces == ["notes"])
        #expect(member.grant?.writeBudget == 100)
    }
}

/// Grants narrower than the library (from the fix-051 branch, folded into 0.5.0): the session is `denied` only when its
/// member lost access it was granted, never because the library declares namespaces this member never had, including
/// after an approval that narrowed the request. Revisions are published only for what the member can read.
@MainActor struct GrantedNamespacesTests {
    /// The namespaces published in the snapshot, without the authority's own revision.
    private func published(_ session: ColophonSession) -> Set<String> {
        Set(session.namespaceRevisions.keys.filter { $0 != "colophon.authority" })
    }

    @Test(arguments: [
        (["listening.podcasts"], ["listening.podcasts", "reading.saved", "notes", "reading.books"]),
        (["reading.saved"], ["reading.saved", "notes"]),
        (["reading.saved", "notes"], ["reading.saved", "notes"]),
    ])
    func aMemberOfAWiderLibraryIsReadyAndPublishesOnlyItsOwn(namespaces: [String], library: [String]) async throws {
        let device = Device(namespaces: namespaces, libraryNamespaces: library)
        await device.session.create()
        #expect(device.session.phase == .ready, "\(device.session.phase) \(device.session.lastError ?? "")")
        #expect(published(device.session) == Set(namespaces), "\(device.session.namespaceRevisions)")
    }

    /// A member of a wider library that is later revoked is still `denied`.
    @Test func aRevokedMemberOfAWiderLibraryIsDenied() async throws {
        let library = ["reading.saved", "notes"]
        let first = Device(namespaces: ["reading.saved"], libraryNamespaces: library)
        await first.session.create()
        try #require(first.session.phase == .ready)
        let second = Device(medium: first.medium, namespaces: ["notes"], libraryNamespaces: library)
        await second.session.restore()
        try await approveByScan(joining: second.session, approving: first.session)
        await second.session.refresh()
        #expect(second.session.phase == .ready, "\(second.session.phase) \(second.session.lastError ?? "")")
        #expect(published(second.session) == ["notes"], "\(second.session.namespaceRevisions)")
        try await first.session.revoke(memberID: try #require(second.session.memberID))
        await second.session.refresh()
        #expect(second.session.phase == .denied, "\(second.session.phase)")
        #expect(second.session.namespaceRevisions.isEmpty)
    }


    /// A device that asks for two namespaces of the library and is granted one (the approver narrows the terms) is
    /// `ready`, publishes only the granted namespace, and is refused a write to the other.
    @Test func aNarrowedApprovalIsReadyAndRefusesTheUngrantedNamespace() async throws {
        let library = ["reading.saved", "notes", "reading.books"]
        let first = Device(namespaces: ["reading.books"], libraryNamespaces: library)
        await first.session.create()
        try #require(first.session.phase == .ready)
        let second = Device(medium: first.medium, namespaces: ["reading.saved", "notes"], libraryNamespaces: library)
        await second.session.restore()
        try await approveByScan(joining: second.session, approving: first.session,
                                grant: GrantOptions(namespaces: ["notes"], access: [.read, .write], expires: nil, writeBudget: nil))
        await second.session.refresh()
        #expect(second.session.phase == .ready, "\(second.session.phase) \(second.session.lastError ?? "")")
        #expect(published(second.session) == ["notes"], "\(second.session.namespaceRevisions)")
        let before = first.medium.snapshot().count
        do {
            try await second.session.perform(try .saveLink(url: URL(string: "https://example.org/x")!, title: "X"), observed: second.session.observedRevision)
            Issue.record("a write to a namespace that was not granted was stored")
        } catch let error as ColophonError {
            guard case .denied(_, let reason, _, _) = error else { Issue.record("expected denied, got \(error)"); return }
            #expect(reason == .notGranted)
        }
        #expect(first.medium.snapshot().count == before, "a refused write stores nothing")
        #expect(second.session.phase == .ready, "\(second.session.phase)")
    }

    /// A member of a wider library whose grant has expired is still `denied`. Driven by the injected clock, no sleeping.
    @Test func anExpiredMemberOfAWiderLibraryIsDenied() async throws {
        let library = ["reading.saved", "notes"]
        let clock = Clock()
        let first = Device(namespaces: ["reading.saved"], libraryNamespaces: library, clock: { clock.now })
        await first.session.create()
        try #require(first.session.phase == .ready)
        let second = Device(medium: first.medium, namespaces: ["notes"], libraryNamespaces: library, clock: { clock.now })
        await second.session.restore()
        let expires = ISO8601DateFormatter().string(from: clock.now.addingTimeInterval(3600))
        try await approveByScan(joining: second.session, approving: first.session,
                                grant: GrantOptions(namespaces: ["notes"], access: [.read, .write], expires: expires, writeBudget: nil))
        await second.session.refresh()
        #expect(second.session.phase == .ready, "\(second.session.phase) \(second.session.lastError ?? "")")
        #expect(published(second.session) == ["notes"], "\(second.session.namespaceRevisions)")
        clock.advance(by: 7200)
        await second.session.refresh()
        #expect(second.session.phase == .denied, "\(second.session.phase)")
        #expect(second.session.namespaceRevisions.isEmpty)
    }
}
