import Foundation
import Observation

/// A bounded set of typed query slices. Rendering reads cached(), never decodes or folds.
/// Await load() for cold completion (including widgets); warming is independently observable.
@Observable @MainActor public final class NamespaceStore<Query: Hashable & Sendable, Result: Sendable> {
    public enum State: Equatable { case idle, warming, ready, unavailable }
    public private(set) var state: State = .idle
    public private(set) var revision: UInt64 = 0
    public let namespace: String
    private var results: [Query: Result] = [:]
    @ObservationIgnored private let session: ColophonSession
    @ObservationIgnored private let evaluate: @Sendable (Query, Data) throws -> Result
    @ObservationIgnored private var loader: (@Sendable (Query) async throws -> Result)?
    @ObservationIgnored private var generation: UInt64 = 0
    @ObservationIgnored private var isClosed = false
    @ObservationIgnored private var registration: UUID?
    @ObservationIgnored private let maximumQueries: Int
    public init(session: ColophonSession, namespace: String, maximumQueries: Int = 64,
                evaluate: @escaping @Sendable (Query, Data) throws -> Result) {
        self.session = session; self.namespace = namespace; self.evaluate = evaluate
        self.maximumQueries = max(1, maximumQueries)
        registration = session.registerCache { [weak self] changed, lost in
            guard let self, lost || changed.contains(namespace) else { return }
            generation &+= 1
            results = [:]; revision = self.session.namespaceRevisions[namespace, default: 0]
            state = lost ? .unavailable : .idle
        }
    }
    /// Named-query mode avoids taking a compatibility whole-state projection.
    public convenience init(session: ColophonSession, namespace: String, maximumQueries: Int = 64,
                            load: @escaping @Sendable (Query) async throws -> Result) {
        self.init(session: session, namespace: namespace, maximumQueries: maximumQueries) { _, _ in
            throw SessionError.notReady
        }
        loader = load
    }
    isolated deinit { if let registration { session.unregisterCache(registration) } }
    public func cached(_ query: Query) -> Result? { results[query] }
    @discardableResult public func load(_ query: Query) async throws -> Result {
        await session.restore()
        guard !isClosed else { throw SessionError.notReady }
        if let result = results[query] { return result }
        let loadGeneration = generation
        let lease = session.context
        let observed = session.namespaceRevisions[namespace, default: 0]
        state = .warming
        do {
            let result: Result
            if let loader { result = try await loader(query) }
            else { result = try await Self.compute(query, data: session.projection(namespace: namespace), evaluate: evaluate) }
            guard !isClosed, generation == loadGeneration, session.context == lease, session.phase == .ready,
                  session.namespaceRevisions[namespace, default: 0] == observed else { throw SessionError.staleRevision }
            if results.count >= maximumQueries { results = [:] }
            results[query] = result; revision = observed; state = .ready
            return result
        } catch {
            if generation == loadGeneration, !isClosed { state = .unavailable }
            throw error
        }
    }
    public func close() { isClosed = true; generation &+= 1; if let registration { session.unregisterCache(registration) }; registration = nil; results = [:]; state = .unavailable }
    @concurrent private static func compute(_ query: Query, data: Data,
                                            evaluate: @Sendable (Query, Data) throws -> Result) async throws -> Result {
        try Task.checkCancellation(); return try evaluate(query, data)
    }
}

public struct SavedLink: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let url: String
    public let title: String?
    public let deleted: Bool?
}
public struct SavedLinksQuery: Hashable, Sendable {
    public let limit: Int
    public init(limit: Int = 100) { self.limit = max(0, min(limit, 1000)) }
}
extension NamespaceStore where Query == SavedLinksQuery, Result == [SavedLink] {
    public convenience init(savedLinksIn session: ColophonSession) {
        self.init(session: session, namespace: "reading.saved") { query, bytes in
            return Array(try JSONDecoder().decode(SavedLinksProjection.self, from: bytes).items.lazy.filter { $0.deleted != true }.prefix(query.limit))
        }
    }
}

private struct SavedLinksProjection: Decodable { let items: [SavedLink] }
