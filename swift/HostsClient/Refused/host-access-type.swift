// expect: SessionHostAccess
import Foundation
// The type that hands out the engine and the signer cannot be named.
import ColophonSession
func reach(_ access: SessionHostAccess) async throws { _ = try await access.signRaw(Data()) }
