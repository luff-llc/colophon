import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
import ColophonSession

/// A session whose library declares more namespaces than its own member was granted (`libraryNamespaces` wider than
/// `namespaces`). The session is `denied` only when its member lost access it was granted, never because the library
/// declares namespaces this member never had (docs/session.md, Phases).
@MainActor struct LibraryNamespacesTests {
    /// The namespaces published in the snapshot, without the authority's own revision.
    private func published(_ session: ColophonSession) -> Set<String> {
        Set(session.namespaceRevisions.keys.filter { $0 != "colophon.authority" })
    }

    @Test(arguments: [
        (["listening.podcasts"], ["listening.podcasts", "reading.saved", "notes", "reading.books"]),
        (["reading.saved"], ["reading.saved", "notes"]),
        (["reading.saved", "notes"], ["reading.saved", "notes"]),
    ])
    func aMemberOfAWiderLibraryIsReadyAfterCreation(namespaces: [String], library: [String]) async throws {
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
