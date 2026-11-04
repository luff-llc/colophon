import ColophonCore
import Foundation

public enum BooklistRecordError: Error, Equatable {
  case emptySourceIdentity
  case missingStatus
}

/// A typed view of one Booklist source row. The original JSON object is the export authority.
public struct BooklistRecordAdapter: Sendable, Equatable, Identifiable {
  public enum ReadingStatus: String, Sendable {
    case wantToRead
    case reading
    case finished
  }

  public static let sourceSystem = "toolsperson-booklist"

  public let sourceLibrary: String
  public let legacyID: String
  public let raw: [String: JSONValue]
  public let sourceStatus: String
  public let title: String?
  public let author: String?
  public let started: String?
  public let finished: String?
  public let notes: JSONValue?
  public let readingStatus: ReadingStatus?
  public let readYear: Int?

  /// Namespaced and length-delimited so distinct source/library/row tuples cannot alias.
  public var id: String {
    let tuple = "\(Self.sourceSystem):\(sourceLibrary.utf8.count):\(sourceLibrary):\(legacyID.utf8.count):\(legacyID)"
    return "booklist:" + Canonical.digest(Data(tuple.utf8))
  }

  public init(sourceLibrary: String, legacyID: String, raw: [String: JSONValue]) throws {
    guard !sourceLibrary.isEmpty, !legacyID.isEmpty else { throw BooklistRecordError.emptySourceIdentity }
    guard let status = raw["Status"]?.string ?? raw["status"]?.string else {
      throw BooklistRecordError.missingStatus
    }
    self.sourceLibrary = sourceLibrary
    self.legacyID = legacyID
    self.raw = raw
    sourceStatus = status
    title = raw["title"]?.string ?? raw["Title"]?.string
    author = raw["author"]?.string ?? raw["Author"]?.string
    started = raw["started"]?.string ?? raw["Started"]?.string
    finished = raw["finished"]?.string ?? raw["Finished"]?.string
    notes = raw["notes"] ?? raw["Notes"]
    switch status {
    case "Wish List": readingStatus = .wantToRead; readYear = nil
    case "Reading": readingStatus = .reading; readYear = nil
    case _ where status.count == 12 && status.hasPrefix("Read in ")
      && status.suffix(4).allSatisfy({ $0.isASCII && $0.isNumber }):
      readingStatus = .finished
      readYear = Int(status.suffix(4))
    default: readingStatus = nil; readYear = nil
    }
  }

  /// Retains unknown fields, dates, note text, and JSON nulls exactly as received.
  public func export() -> [String: JSONValue] { raw }
}
