// expect: current
import Foundation
// The endpoint is internal: only the host's queue calls it.
import ColophonHosts
func reach(_ host: SessionCellHost) throws { _ = try host.current?.tick(engine: fatalError(), clock: fatalError()) }
