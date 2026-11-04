import ColophonCore
import ColophonStore
import Foundation

/// Freshly verified enrollment requests, independent of request-provider availability.
/// Unreadable records never hide another verified request or imply membership authority.
public struct EnrollmentRequestScan: Sendable {
  public enum Availability: Sendable, Equatable {
    case complete
    case incomplete(unavailableRecords: Int)
    case unavailable
  }

  public let requests: [EnrollmentRequest]
  public let availability: Availability

  public static func read(store: any RecordStore, authority: AuthorityState) -> Self {
    let names: [String]
    do { names = try store.list(LibraryPath.requests) }
    catch { return Self(requests: [], availability: .unavailable) }
    var requests: [EnrollmentRequest] = []
    var unavailable = 0
    for name in names {
      let bytes: Data?
      do { bytes = try store.read(LibraryPath.requests + "/" + name) }
      catch { unavailable += 1; continue }
      guard let bytes else { unavailable += 1; continue }
      guard let record = try? Canonical.decode(SignedRecord.self, from: bytes),
        let request = try? Canonical.decode(EnrollmentRequest.self, from: record.body),
        request.member.verify(record), authority.members[request.id] == nil else { continue }
      requests.append(request)
    }
    return Self(requests: requests.sorted { $0.created < $1.created },
      availability: unavailable == 0 ? .complete : .incomplete(unavailableRecords: unavailable))
  }
}
