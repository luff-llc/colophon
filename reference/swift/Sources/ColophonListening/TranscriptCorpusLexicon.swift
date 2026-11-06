import Foundation

/// Deterministic offline lexical recall. English suffix normalization is deliberately small;
/// this is not semantic search. Han characters are indexed individually so Chinese requires
/// no downloaded language model. Queries require most meaningful terms in each returned passage.
enum TranscriptCorpusLexicon {
  static func terms(_ text: String) -> [String] { tokens(text).map(\.term) }

  static func tokens(_ text: String) -> [(term: String, start: Int, length: Int)] {
    var result: [(String, Int, Int)] = []
    var word = ""
    var wordStart = 0
    var wordLength = 0
    var offset = 0
    func flush() {
      let folded = word.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive],
        locale: Locale(identifier: "en_US_POSIX"))
      if !folded.isEmpty { result.append((stem(folded), wordStart, wordLength)) }
      word = ""; wordLength = 0
    }
    for scalar in text.unicodeScalars {
      let length = scalar.utf16.count
      if isHan(scalar.value) {
        flush()
        result.append((String(scalar), offset, length))
      } else if CharacterSet.alphanumerics.contains(scalar) || CharacterSet.nonBaseCharacters.contains(scalar) {
        if word.isEmpty { wordStart = offset }
        word.unicodeScalars.append(scalar)
        wordLength += length
      } else { flush() }
      offset += length
    }
    flush()
    return result
  }

  static func queryTerms(_ query: String) -> Set<String> {
    let stopwords: Set<String> = ["a", "an", "the", "and", "or", "of", "to", "in", "on", "at", "for",
      "from", "with", "about", "what", "which", "who", "where", "when", "why", "how", "do", "did",
      "does", "is", "are", "was", "were", "be", "been", "have", "has", "had", "it", "this", "that",
      "i", "me", "my", "we", "our", "you", "your", "they", "their", "can", "could", "would", "please"]
    return Set(terms(query)).subtracting(stopwords.map(stem))
  }

  private static func isHan(_ scalar: UInt32) -> Bool {
    (0x3400...0x4DBF).contains(scalar) || (0x4E00...0x9FFF).contains(scalar)
      || (0xF900...0xFAFF).contains(scalar) || (0x20000...0x323AF).contains(scalar)
  }

  private static func stem(_ word: String) -> String {
    guard word.unicodeScalars.allSatisfy({ (97...122).contains($0.value) }), word.count > 3 else { return word }
    if word.hasSuffix("ies"), word.count > 4 { return String(word.dropLast(3)) + "y" }
    for suffix in ["ing", "ed"] where word.hasSuffix(suffix) && word.count > suffix.count + 2 {
      var base = String(word.dropLast(suffix.count))
      if base.count > 2, let last = base.last, base.dropLast().last == last,
        "bdgmnprt".contains(last) { base.removeLast() }
      return base
    }
    if word.hasSuffix("s"), !word.hasSuffix("ss"), !word.hasSuffix("us"), !word.hasSuffix("is") {
      return String(word.dropLast())
    }
    return word
  }

  /// Chunks on Character boundaries to keep UTF-16 offsets valid for emoji and combining
  /// sequences. A small overlap preserves queries near a boundary without duplicate results.
  static func passages(_ text: String) -> [(start: Int, text: String)] {
    guard !text.isEmpty else { return [] }
    var result: [(Int, String)] = []
    var start = text.startIndex
    var startUTF16 = 0
    while start < text.endIndex {
      var end = start
      var length = 0
      while end < text.endIndex {
        let next = text.index(after: end)
        let count = text[end..<next].utf16.count
        if length > 0 && length + count > 700 { break }
        length += count
        end = next
      }
      result.append((startUTF16, String(text[start..<end])))
      if end == text.endIndex { break }
      var nextStart = end
      var overlap = 0
      while nextStart > start && overlap < 100 {
        let previous = text.index(before: nextStart)
        overlap += text[previous..<nextStart].utf16.count
        nextStart = previous
      }
      // A pathological grapheme can itself exceed the normal chunk bound.
      if nextStart == start { nextStart = end; overlap = 0 }
      startUTF16 += length - overlap
      start = nextStart
    }
    return result
  }
}
