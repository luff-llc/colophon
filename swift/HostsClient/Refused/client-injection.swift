// expect: extra arguments at positions #1, #4
import Foundation
// A stream client cannot be handed to a host (and so kept and called outside it): the initializer that takes
// `source:` and `client:` is internal, so only the public one is seen, and both arguments are refused.
import ColophonHosts
import ColophonSession
func reach(_ client: HomeStream, _ transport: any HomeTransport) async throws {
    _ = try await HomeStreamHost(source: fatalError(), home: "h", transport: transport, client: client)
}
