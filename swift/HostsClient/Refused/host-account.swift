// expect: HostAccount
import Foundation
// The account protocol with the engine and the raw signer is internal.
import ColophonHosts
func reach(_ account: any HostAccount) async throws { _ = try await account.signRaw(Data()) }
