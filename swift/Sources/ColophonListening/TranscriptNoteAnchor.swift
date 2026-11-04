import ColophonCore
import Foundation

/// Exact text in one immutable, signed transcript revision. Offsets count UTF-16 code units
/// in the saved document, not characters in a rendered or normalized passage.
public struct TranscriptNoteAnchor: Codable, Hashable, Sendable {
  public let reference: SharedTranscriptReference
  public let startUTF16: Int
  public let lengthUTF16: Int
  public let quote: String

  public init(reference: SharedTranscriptReference, startUTF16: Int, lengthUTF16: Int, quote: String) {
    self.reference = reference
    self.startUTF16 = startUTF16
    self.lengthUTF16 = lengthUTF16
    self.quote = quote
  }

  public func matches(_ document: TranscriptDocument) -> Bool {
    let count = document.text.utf16.count
    guard startUTF16 >= 0, startUTF16 <= count, lengthUTF16 > 0,
      lengthUTF16 <= count - startUTF16, !quote.isEmpty,
      let range = Range(NSRange(location: startUTF16, length: lengthUTF16), in: document.text)
    else { return false }
    return document.text[range] == quote
  }

  public var json: JSONValue {
    .object([
      "reference": .object([
        "libraryID": .string(reference.libraryID), "episode": .string(reference.episode),
        "show": .string(reference.show), "revision": .string(reference.revision),
        "blob": reference.blob.json
      ]),
      "startUTF16": .number(Double(startUTF16)),
      "lengthUTF16": .number(Double(lengthUTF16)),
      "quote": .string(quote)
    ])
  }

  public init?(json: JSONValue?) {
    guard let object = json?.object, let rawReference = object["reference"],
      let data = try? Canonical.encode(rawReference),
      let reference = try? Canonical.decode(SharedTranscriptReference.self, from: data),
      let start = object["startUTF16"]?.int, let length = object["lengthUTF16"]?.int,
      let quote = object["quote"]?.string
    else { return nil }
    self.init(reference: reference, startUTF16: start, lengthUTF16: length, quote: quote)
  }
}
