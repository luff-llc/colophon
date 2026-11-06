import Observation
import ColophonSession

/// Keep one store per session. Load from actions/tasks; render cached plain values.
@Observable @MainActor public final class ListeningStore {
    private let cache: NamespaceStore<DomainQueryKey, any Sendable>
    public var revision: UInt64 { cache.revision }
    public var state: NamespaceStore<DomainQueryKey, any Sendable>.State { cache.state }
    public init(session: ColophonSession, maximumQueries: Int = 64) {
        cache = NamespaceStore(session: session, namespace: "listening.podcasts", maximumQueries: maximumQueries,
                               load: { try await $0.evaluate(session: session) })
    }
    public func cached<Q: ListeningDomainQuery>(_ query: Q) -> DomainQueryResult<Q.Value>? {
        guard let key = try? DomainQueryKey(query) else { return nil }
        return cache.cached(key) as? DomainQueryResult<Q.Value>
    }
    @discardableResult public func load<Q: ListeningDomainQuery>(_ query: Q) async throws -> DomainQueryResult<Q.Value> {
        let result = try await cache.load(DomainQueryKey(query))
        guard let typed = result as? DomainQueryResult<Q.Value> else { throw SessionError.invalidCommand }
        return typed
    }
    public func close() { cache.close() }
}
