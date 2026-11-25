// expect: hostAccess
import Foundation
// There is no SPI to opt into.
@_spi(Hosts) import ColophonSession
@MainActor func reach(_ session: ColophonSession) async throws { _ = try await session.hostAccess.engine() }
