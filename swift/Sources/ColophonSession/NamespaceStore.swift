import Foundation
import Observation

/// A bounded set of typed query slices. Rendering reads cached(), never decodes or folds.
/// Await load() for cold completion (including widgets); warming is independently observable.
///
/// Entries are keyed by query and by the namespace revision they were read at. A namespace change
/// does not discard them: `cached` stops returning them (it serves only current values), while
/// `latest` keeps returning the last value so a view never blanks while it reloads. Only queries
/// that are loaded again are re-read, concurrent loads of one query share one read, and the bound
/// evicts stale entries first. Loss of readiness still clears everything.
@Observable @MainActor public final class NamespaceStore<Query: Hashable & Sendable, Result: Sendable> {
    public enum State: Equatable { case idle, warming, ready, unavailable }
    public private(set) var state: State = .idle
    public private(set) var revision: UInt64 = 0
    public let namespace: String
    private var results: [Query: Entry] = [:]
    @ObservationIgnored private var useOrder: [Query] = []
    @ObservationIgnored private var inFlight: [Query: (revision: UInt64, generation: UInt64, task: Task<Result, any Error>)] = [:]
    @ObservationIgnored private let session: ColophonSession
    @ObservationIgnored private let evaluate: @Sendable (Query, Data) throws -> Result
    @ObservationIgnored private var loader: (@Sendable (Query) async throws -> Result)?
    @ObservationIgnored private var generation: UInt64 = 0
    @ObservationIgnored private var isClosed = false
    @ObservationIgnored private var registration: UUID?
    @ObservationIgnored private let maximumQueries: Int
    /// Reads served by the loader or evaluator, for tests that prove incremental reloads.
    @ObservationIgnored public private(set) var reads = 0
    private struct Entry { let result: Result; let revision: UInt64 }
    public init(session: ColophonSession, namespace: String, maximumQueries: Int = 64,
                evaluate: @escaping @Sendable (Query, Data) throws -> Result) {
        self.session = session; self.namespace = namespace; self.evaluate = evaluate
        self.maximumQueries = max(1, maximumQueries)
        registration = session.registerCache { [weak self] changed, lost in
            guard let self, lost || changed.contains(namespace) else { return }
            generation &+= 1
            revision = self.session.namespaceRevisions[namespace, default: 0]
            if lost { results = [:]; useOrder = []; inFlight = [:] }
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
    private var currentRevision: UInt64 { session.namespaceRevisions[namespace, default: 0] }
    /// The value read at the current namespace revision, or nil.
    public func cached(_ query: Query) -> Result? {
        guard let entry = results[query], entry.revision == currentRevision else { return nil }
        return entry.result
    }
    /// The last value read for `query`, current or not. Render it while `load` refreshes.
    public func latest(_ query: Query) -> (value: Result, current: Bool)? {
        results[query].map { ($0.result, $0.revision == currentRevision) }
    }
    @discardableResult public func load(_ query: Query) async throws -> Result {
        await session.restore()
        guard !isClosed else { throw SessionError.notReady }
        if let result = cached(query) { touch(query); return result }
        let loadGeneration = generation
        let lease = session.context
        let observed = currentRevision
        if let running = inFlight[query], running.revision == observed, running.generation == loadGeneration {
            return try await running.task.value
        }
        state = .warming
        let loader = loader, evaluate = evaluate, session = session, namespace = namespace
        let task = Task<Result, any Error> { @MainActor in
            if let loader { return try await loader(query) }
            return try await Self.compute(query, data: session.projection(namespace: namespace), evaluate: evaluate)
        }
        inFlight[query] = (observed, loadGeneration, task)
        reads += 1
        defer { if inFlight[query]?.generation == loadGeneration, inFlight[query]?.revision == observed { inFlight[query] = nil } }
        do {
            let result = try await task.value
            guard !isClosed, generation == loadGeneration, session.context == lease, session.phase == .ready,
                  currentRevision == observed else { throw SessionError.staleRevision }
            store(query, Entry(result: result, revision: observed))
            revision = observed; state = .ready
            return result
        } catch {
            if generation == loadGeneration, !isClosed { state = .unavailable }
            throw error
        }
    }
    private func touch(_ query: Query) {
        if let index = useOrder.firstIndex(of: query) { useOrder.remove(at: index) }
        useOrder.append(query)
    }
    private func store(_ query: Query, _ entry: Entry) {
        if results[query] == nil, results.count >= maximumQueries {
            // Evict the least recently used stale entry, else the least recently used one.
            let current = currentRevision
            let victim = useOrder.first { results[$0]?.revision != current } ?? useOrder.first
            if let victim { results[victim] = nil; useOrder.removeAll { $0 == victim } }
        }
        results[query] = entry
        touch(query)
    }
    public func close() {
        isClosed = true; generation &+= 1
        if let registration { session.unregisterCache(registration) }
        registration = nil; results = [:]; useOrder = []; inFlight = [:]; state = .unavailable
    }
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
