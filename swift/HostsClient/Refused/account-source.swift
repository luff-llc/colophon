// expect: source
import Foundation
// The account behind the opaque wrapper is internal.
import ColophonHosts
func reach(_ account: ColophonHostAccount) async throws { _ = try await account.source.engine() }
