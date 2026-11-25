import Foundation
import os

/// What the 0.6 hosts (`ColophonHosts`) need from a restored session: the member engine as it is now, the
/// `colophon.home.stream` call, an ordinary exchange pass, the member key for one raw signature, and a home's transport.
///
/// It is SPI (`@_spi(Hosts)`): an application reaches it only through `ColophonHosts`. The session keeps owning the
/// engine, its lock and its exchange; this only reaches them.
@_spi(Hosts) public struct SessionHostAccess: Sendable {
    let worker: SessionWorker
    /// Runs one exchange pass through the session (its own `syncNow`), so passes never overlap with its poll loop.
    let pass: @Sendable () async -> Bool
    private let cache = OSAllocatedUnfairLock<(ObjectIdentifier, AccountEngine)?>(initialState: nil)

    init(worker: SessionWorker, pass: @escaping @Sendable () async -> Bool) { self.worker = worker; self.pass = pass }

    /// The member engine as it is now. A locked engine fails its calls (`locked`); a reopened one is another engine.
    ///
    /// The engine's handle is taken once per `ColophonEngine` and kept, so that a stream or endpoint call does not wait
    /// behind a long engine call on the engine's queue: the core's objects serialize their own calls, and an endpoint
    /// reads the engine's gate, never its lock (docs/bindings-05.md §10).
    public func engine() async throws -> AccountEngine {
        let current = try await worker.requireEngine()
        let id = ObjectIdentifier(current)
        if let (held, engine) = cache.withLock({ $0 }), held == id { return engine }
        let engine = try await current.run { $0 }
        cache.withLock { $0 = (id, engine) }
        return engine
    }
    /// The `colophon.home.stream` call for `home`, signed and judged by the core, as the envelope's bytes.
    public func streamCall(home: String) async throws -> Data { try await worker.streamCall(home: home) }
    /// One ordinary exchange pass with the homes. Throws when it did not finish.
    public func exchange() async throws {
        guard await pass() else { throw SessionError.notReady }
    }
    /// A raw P-256 signature (`r || s`) by this device's member key over `body`.
    public func signRaw(_ body: Data) async throws -> Data { try await worker.signRaw(body) }
    /// The transport this session was configured with for `home`, if any.
    public func transport(home: String) async -> (any HomeTransport)? { await worker.transport(home: home) }
}

extension ColophonSession {
    /// The 0.6 hosts' access to this session (`ColophonHosts.SessionHostAccount`).
    @_spi(Hosts) public var hostAccess: SessionHostAccess {
        SessionHostAccess(worker: worker, pass: { [weak self] in await self?.syncNow() ?? false })
    }
}
