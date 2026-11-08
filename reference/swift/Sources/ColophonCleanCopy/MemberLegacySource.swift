import ColophonAuthority
import ColophonCore
import ColophonMigration
import ColophonReplica
import ColophonStore
import Foundation

/// A 0.1 verifier reading solely as a member. It never receives or requests a root identity.
public struct MemberLegacySource: LegacyLibrarySource {
    private let records: [String: Data]
    private let reader: any Identity

    /// Capture exact immutable bytes from a MemoryStore, without retaining a mutable store handle.
    public init(snapshot: MemoryStore, readerIdentity: any Identity) {
        records = snapshot.snapshot; reader = readerIdentity
    }

    /// Replay the original authority, admission, epochs, signatures and replica order.
    public func snapshot(namespaces: Set<String>) throws -> any LegacyLibrarySnapshot {
        guard !namespaces.isEmpty, namespaces.isSubset(of: Set(SourceReader.namespaces)) else { throw MigrationError.invalidSource }
        let store = try memoryStore(records)
        let source = try SourceReader.read(store: store, reader: reader, namespaces: namespaces)
        return ReferenceSnapshot(source: source, readerID: try reader.availablePublicIdentity().id, namespaces: namespaces)
    }
}

/// A signed request exported for a controller to approve through the original library.
public struct ReaderRequest: Codable, Sendable, Equatable {
    /// Relative request path inside the private snapshot.
    public let path: String
    /// Exact signed 0.1 request bytes, suitable for transfer by the person.
    public let bytes: Data
    /// Pairing code to compare with the approving device.
    public let pairingCode: String
    /// Dedicated software member ID, stable across reruns.
    public let memberID: String
    /// Every namespace declared by the verified old authority.
    public let namespaces: [String]
}

extension CleanCopyWorkspace {
    /// Create or re-export “Clean copy (Mac)” read-only enrollment. Writes only private workspace
    /// files and the snapshot's requests area. Run snapshot again after external approval.
    public func request() throws -> ReaderRequest {
        let lease = try WorkspaceLease(directory: directory)
        defer { lease.close() }
        try assertSourceUnchanged()
        let records = try snapshotRecords()
        let store = try memoryStore(records)
        let authority = try AuthorityLog(store: store).state()
        let url = directory.appendingPathComponent("reader-request.json")
        if FileManager.default.fileExists(atPath: url.path) {
            let existing = try JSONDecoder().decode(ReaderRequest.self, from: Data(contentsOf: url))
            guard existing.memberID == (try readerIdentity()).id, existing.namespaces == authority.namespaces else {
                throw CleanCopyError.workspaceMismatch
            }
            return existing
        }
        let identity = try readerIdentity(create: true)
        let replica = Replica(store: store, identity: identity)
        _ = try replica.requestEnrollment(label: "Clean copy (Mac)", role: .device, namespaces: authority.namespaces, write: false)
        let path = LibraryPath.request(identity.id)
        guard let bytes = try store.read(path) else { throw MigrationError.sourceUnavailable(path) }
        let request = ReaderRequest(path: path, bytes: bytes, pairingCode: try replica.pairingCode(), memberID: identity.id,
                                    namespaces: authority.namespaces)
        try writePrivate(bytes, to: snapshotDirectory.appendingPathComponent(path))
        try writePrivate(bytes, to: directory.appendingPathComponent("enrollment-request.json"))
        try writePrivate(try encode(request), to: url)
        try assertSourceUnchanged()
        return request
    }

    /// Verify the dedicated reader's grant from the most recent snapshot, including every epoch.
    public func readerApproved() throws -> Bool {
        let store = try memoryStore(snapshotRecords())
        let authority = try AuthorityLog(store: store).state()
        let identity = try readerIdentity()
        guard let grant = authority.members[identity.id]?.current,
              authority.members[identity.id]?.revokedAt == nil,
              grant.expires.map({ $0 > Date.now }) ?? true,
              Set(authority.namespaces).isSubset(of: Set(grant.namespaces)) else { return false }
        return authority.namespaces.allSatisfy { namespace in
            authority.allEpochs(of: namespace).allSatisfy { authority.keys[namespace]?[$0]?[identity.id] != nil }
        }
    }

    func readerIdentity(create: Bool = false) throws -> SoftwareIdentity {
        let url = directory.appendingPathComponent("reader-identity.json")
        if FileManager.default.fileExists(atPath: url.path) {
            let identity = try JSONDecoder().decode(SoftwareIdentity.self, from: Data(contentsOf: url))
            _ = try identity.availablePublicIdentity()
            return identity
        }
        guard create else { throw CleanCopyError.approvalRequired }
        let identity = SoftwareIdentity()
        try writePrivate(try encode(identity), to: url)
        return identity
    }
    func source() throws -> MemberLegacySource {
        guard try readerApproved() else { throw CleanCopyError.approvalRequired }
        return MemberLegacySource(snapshot: try memoryStore(snapshotRecords()), readerIdentity: try readerIdentity())
    }
}

func memoryStore(_ records: [String: Data]) throws -> MemoryStore {
    let store = MemoryStore()
    for (path, bytes) in records { try store.create(path, bytes) }
    return store
}
