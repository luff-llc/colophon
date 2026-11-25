// expect: client
import Foundation
// A stream client cannot be handed to a host (and so kept and called outside it).
import ColophonHosts
import ColophonSession
func reach(_ client: HomeStream, _ transport: any HomeTransport) async throws {
    _ = try await HomeStreamHost(source: fatalError(), home: "h", transport: transport, client: client)
}
