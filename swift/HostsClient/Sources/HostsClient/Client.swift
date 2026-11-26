import Foundation
import ColophonHosts
import ColophonListeningKit
import ColophonSession

/// A carrier that carries nothing: enough to open a cell with no home.
public struct Nowhere: CellCarrier {
    public init() {}
    public func attach(_ cell: any StreamCell) async throws { cell.linkUp() }
    public func detach(_ cell: any StreamCell) async {}
    public func sendSession(_ frame: String) async -> Bool { false }
    public func onPass(_ listener: @escaping @Sendable () -> Void) async -> ListenerToken? { nil }
}

/// What an app does with the public API only: the host account from its session, a cell host, and its state.
@MainActor public func openCell(session: ColophonSession, store: any ClaimStore, carrier: any CellCarrier = Nowhere()) async throws -> CellSession {
    let account = try ColophonHostAccount(session: session)
    return try await CellSession.join(CellHostOptions(account: account, carrier: carrier, namespace: "listening.podcasts", cell: "now-playing", store: store))
}

/// A stream host over a home, from the public API only (compiled, not run: it needs a home).
@MainActor public func openStream(session: ColophonSession, home: String, transport: any HomeTransport) async throws -> HomeStreamHost {
    let stream = try await HomeStreamHost(account: try ColophonHostAccount(session: session), home: home, transport: transport)
    stream.start()
    return stream
}

/// The `now-playing` cell as a player sets it up, from the public API only: its session, its stream host and one SQLite
/// file for the claim (compiled, not run: it needs a home).
@MainActor public func openNowPlaying(session: ColophonSession, stream: HomeStreamHost, database: URL) async -> NowPlayingSession {
    await NowPlayingSession.open(session: session, stream: stream, claimsDatabase: database, options: NowPlayingOptions(label: "Kitchen iPad"))
}

