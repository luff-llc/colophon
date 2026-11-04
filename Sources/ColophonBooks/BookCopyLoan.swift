import ColophonCore
import Foundation

/// The physical copy's return state, stored in `Bookshelf.Book.extra["copyLoan"]`.
/// A return is a confirmed human decision; an agent may produce a proposal but cannot accept it.
public struct BookCopyLoan: Sendable, Equatable {
  public enum Status: String, Sendable {
    case needsReturn
    case returned
  }

  public static let key = "copyLoan"
  public static let version = 1

  public let status: Status
  /// Identifies the accepted return event. Nil while the copy still needs return.
  public let requestID: String?
  public let reflection: String?
  public let provenance: BookIntentProvenance?

  public init(status: Status, requestID: String? = nil, reflection: String? = nil,
    provenance: BookIntentProvenance? = nil) {
    self.status = status
    self.requestID = requestID
    self.reflection = reflection
    self.provenance = provenance
  }

  public init?(json: JSONValue) {
    guard let object = json.object, object["version"]?.int == Self.version,
      let statusText = object["status"]?.string, let status = Status(rawValue: statusText)
    else { return nil }
    let requestID = object["requestID"]?.string
    let reflection = object["reflection"]?.string
    let provenance = object["provenance"].flatMap(BookIntentProvenance.init(json:))
    if status == .returned {
      guard let requestID, !requestID.isEmpty, let provenance, provenance.confirmedByUser else { return nil }
    }
    self.init(status: status, requestID: requestID, reflection: reflection, provenance: provenance)
  }

  public var json: JSONValue {
    .object([
      "version": .number(Double(Self.version)),
      "status": .string(status.rawValue),
      "requestID": JSONValue(requestID),
      "reflection": JSONValue(reflection),
      "provenance": provenance?.json ?? .null,
    ])
  }
}

/// Records who suggested a change and which person explicitly accepted it.
public struct BookIntentProvenance: Sendable, Equatable {
  public let producerID: String
  public let acceptingUserID: String
  public let confirmedByUser: Bool
  public let sourceQuote: String?
  public let sourceContext: String?

  public init(producerID: String, acceptingUserID: String, confirmedByUser: Bool,
    sourceQuote: String? = nil, sourceContext: String? = nil) {
    self.producerID = producerID
    self.acceptingUserID = acceptingUserID
    self.confirmedByUser = confirmedByUser
    self.sourceQuote = sourceQuote
    self.sourceContext = sourceContext
  }

  public init?(json: JSONValue) {
    guard let object = json.object, let producerID = object["producerID"]?.string,
      let acceptingUserID = object["acceptingUserID"]?.string,
      let confirmedByUser = object["confirmedByUser"]?.bool
    else { return nil }
    self.init(producerID: producerID, acceptingUserID: acceptingUserID, confirmedByUser: confirmedByUser,
      sourceQuote: object["sourceQuote"]?.string, sourceContext: object["sourceContext"]?.string)
  }

  public var json: JSONValue {
    .object(["producerID": .string(producerID), "acceptingUserID": .string(acceptingUserID),
      "confirmedByUser": .bool(confirmedByUser), "sourceQuote": JSONValue(sourceQuote),
      "sourceContext": JSONValue(sourceContext)])
  }
}

public extension Bookshelf.Book {
  var copyLoan: BookCopyLoan? { extra[BookCopyLoan.key].flatMap(BookCopyLoan.init(json:)) }
}
