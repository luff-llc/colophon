// expect: hostAccess
import Foundation
// The session's host access is `package`: an app cannot reach it.
import ColophonSession
@MainActor func reach(_ session: ColophonSession) { _ = session.hostAccess }
