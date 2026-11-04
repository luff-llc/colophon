import ColophonCore
import ColophonListening
import Foundation
import Testing

@Suite struct TranscriptRenderedIndexTests {
  private func reference(_ revision: String = "source-1") -> SharedTranscriptReference {
    SharedTranscriptReference(libraryID: "library", episode: "episode", show: "show",
      revision: revision, blob: BlobRef(digest: "sealed", plain: "plain", epoch: 1, size: 1))
  }

  @Test func unicodeAndDuplicatePassagesKeepDistinctUTF16Offsets() throws {
    let document = TranscriptDocument(text: "Ahead 🐋 café. Again 🐋 café.", words: nil)
    let index = try #require(TranscriptRenderedIndex(document: document, reference: reference(),
      rendered: ["🐋 café", "🐋 café"]))
    let first = try #require(index.exactAnchor(selected: [0]))
    let second = try #require(index.exactAnchor(selected: [1]))
    let combined = try #require(index.exactAnchor(selected: [0, 1]))

    #expect(first.startUTF16 == 6)
    #expect(second.startUTF16 == 21)
    #expect(second.lengthUTF16 == "🐋 café".utf16.count)
    #expect(first.quote == second.quote)
    #expect(combined.quote == "🐋 café. Again 🐋 café")
    #expect(first.matches(document))
    #expect(second.matches(document))
    #expect(index.cueIndex(for: first) == 0)
    #expect(index.cueIndex(for: second) == 1)
    #expect(index.cueIndex(for: combined) == 0)
  }

  @Test func sourceRevisionAndExactQuoteGuardCueLookup() throws {
    let document = TranscriptDocument(text: "First passage. Second passage.", words: nil)
    let original = try #require(TranscriptRenderedIndex(document: document, reference: reference(),
      rendered: ["First passage", "Second passage"]))
    let replacement = try #require(TranscriptRenderedIndex(document: document, reference: reference("source-2"),
      rendered: ["First passage", "Second passage"]))
    let anchor = try #require(original.exactAnchor(selected: [1]))
    let wrongQuote = TranscriptNoteAnchor(reference: reference(), startUTF16: anchor.startUTF16,
      lengthUTF16: anchor.lengthUTF16, quote: "Other passage")

    #expect(original.cueIndex(for: anchor) == 1)
    #expect(replacement.cueIndex(for: anchor) == nil)
    #expect(original.cueIndex(for: wrongQuote) == nil)
  }

  @Test func longUnicodeTranscriptMapsFinalAndCombinedCueExactly() throws {
    let rendered = (0..<2_048).map { "🐋 cue \($0) e\u{301}" }
    let source = "📖 lead · " + rendered.joined(separator: " — ") + " · end"
    let document = TranscriptDocument(text: source, words: nil)
    let index = try #require(TranscriptRenderedIndex(document: document, reference: reference(),
      rendered: rendered))
    let final = try #require(index.exactAnchor(selected: [2_047]))
    let combined = try #require(index.exactAnchor(selected: [2_046, 2_047]))
    let range = try #require(source.range(of: rendered[2_047]))
    let expectedStart = source[..<range.lowerBound].utf16.count
    let expectedQuote = rendered[2_046] + " — " + rendered[2_047]

    #expect(final.startUTF16 == expectedStart)
    #expect(final.lengthUTF16 == rendered[2_047].utf16.count)
    #expect(final.quote == rendered[2_047])
    #expect(combined.quote == expectedQuote)
    #expect(index.cueIndex(for: final) == 2_047)
    #expect(index.cueIndex(for: combined) == 2_046)
  }

  @Test func unmappableOrDisjointRenderingsNeverInventAnAnchor() throws {
    let document = TranscriptDocument(text: "One. Two. Three.", words: nil)
    let normalized = TranscriptRenderedIndex(document: document, reference: reference(),
      rendered: ["One", "TWO"])
    let index = try #require(TranscriptRenderedIndex(document: document, reference: reference(),
      rendered: ["One", "Two", "Three"]))

    #expect(normalized?.reference == nil)
    #expect(index.exactAnchor(selected: [0, 2]) == nil)
    #expect(index.exactAnchor(selected: [-1]) == nil)
    #expect(index.exactAnchor(selected: []) == nil)
  }
}
