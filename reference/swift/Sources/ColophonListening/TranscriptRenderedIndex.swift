import Foundation

/// Ordered rendered passages mapped once to exact UTF-16 slices of one signed transcript.
/// A failed mapping stays unavailable rather than guessing from normalized passage text.
public struct TranscriptRenderedIndex: Sendable {
  private struct Offset: Sendable {
    let start: Int
    let end: Int
  }

  public let reference: SharedTranscriptReference
  private let document: TranscriptDocument
  private let offsets: [Offset]

  public init?(document: TranscriptDocument, reference: SharedTranscriptReference, rendered: [String]) {
    let source = document.text
    var cursor = source.startIndex
    var utf16Cursor = 0
    var offsets: [Offset] = []
    offsets.reserveCapacity(rendered.count)
    for text in rendered {
      guard !text.isEmpty, let match = source.range(of: text, range: cursor..<source.endIndex) else { return nil }
      let start = utf16Cursor + source[cursor..<match.lowerBound].utf16.count
      let end = start + source[match].utf16.count
      offsets.append(Offset(start: start, end: end))
      cursor = match.upperBound
      utf16Cursor = end
    }
    self.document = document
    self.reference = reference
    self.offsets = offsets
  }

  /// Build an exact citation only for one contiguous selection of rendered passages.
  public func exactAnchor(selected: Set<Int>) -> TranscriptNoteAnchor? {
    guard let first = selected.min(), let last = selected.max(),
      offsets.indices.contains(first), offsets.indices.contains(last),
      selected.count == last - first + 1,
      let range = Range(NSRange(location: offsets[first].start,
        length: offsets[last].end - offsets[first].start), in: document.text)
    else { return nil }
    return TranscriptNoteAnchor(reference: reference, startUTF16: offsets[first].start,
      lengthUTF16: offsets[last].end - offsets[first].start, quote: String(document.text[range]))
  }

  /// Locate the cue containing an exact anchor's start; older source revisions never map.
  public func cueIndex(for anchor: TranscriptNoteAnchor) -> Int? {
    guard anchor.reference == reference, anchor.matches(document) else { return nil }
    let start = anchor.startUTF16
    var lower = 0
    var upper = offsets.count
    while lower < upper {
      let middle = lower + (upper - lower) / 2
      if offsets[middle].end <= start { lower = middle + 1 }
      else { upper = middle }
    }
    guard offsets.indices.contains(lower), offsets[lower].start <= start else { return nil }
    return lower
  }
}
