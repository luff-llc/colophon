import ColophonCore
import ColophonStore
import Foundation

/// Separate from EnrollmentRequestScan: old join requests never resurface as scope upgrades.
public struct AdditionalAccessRequestScan: Sendable {
  public let pending: [AdditionalAccessRequest.Record]
  public let withdrawn: [AdditionalAccessRequest.Record]
  public let invalidCount: Int
  public let availability: EnrollmentRequestScan.Availability
  public static func read(store: any RecordStore, authority: AuthorityState, now: Date = .now) -> Self {
    let names: [String]
    do { names = try store.list(LibraryPath.requests) }
    catch { return .init(pending: [], withdrawn: [], invalidCount: 0, availability: .unavailable) }
    var pending: [AdditionalAccessRequest.Record] = [], withdrawn: [AdditionalAccessRequest.Record] = []
    var unavailable = 0, invalid = 0
    for name in names where name.hasPrefix("additional-") && name.hasSuffix(".json") {
      let memberID = String(name.dropFirst("additional-".count).dropLast(".json".count))
      guard memberID.utf8.count == 32, memberID.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
        invalid += 1; continue
      }
      let path = LibraryPath.requests + "/" + name
      let data: Data?
      do { data = try store.read(path) } catch { unavailable += 1; continue }
      guard let data else { unavailable += 1; continue }
      do {
        let record = try AdditionalAccessRequest.Record.decode(data, path: path)
        _ = try record.request.validate(in: authority, now: now, pending: false)
        if record.request.status == .pending { pending.append(record) } else { withdrawn.append(record) }
      } catch { invalid += 1 }
    }
    return .init(pending: pending.sorted { $0.path < $1.path }, withdrawn: withdrawn.sorted { $0.path < $1.path },
      invalidCount: invalid, availability: unavailable == 0 ? .complete : .incomplete(unavailableRecords: unavailable))
  }
}
