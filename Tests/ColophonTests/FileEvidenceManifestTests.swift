import ColophonCore
import Foundation
import Testing

struct FileEvidenceManifestTests {
  private struct Fixture {
    let root: FileEvidenceManifest
    let pages: [String: Data]
    func graph() throws -> FileEvidenceManifest.GraphStructure {
      try root.validateStructure().validateGraph { ref in
        guard let bytes = pages[ref.plain] else { throw FileEvidenceManifestError.pageMismatch }
        return bytes
      }
    }
  }
  private func digest(_ text: String) -> String { Canonical.digest(Data(text.utf8)) }
  private func chunk(size: Int, epoch: Int = 1) -> BlobRef {
    BlobRef(digest: digest("cipher-\(size)-\(epoch)"), plain: digest("plain-\(size)"), epoch: epoch, size: size)
  }
  private func fixture(total: Int64, mixedEpochs: Bool = false) throws -> Fixture {
    let count = total == 0 ? 0 : Int((total - 1) / Int64(FileEvidenceLimits.chunkBytes) + 1)
    var descriptors: [FileEvidenceManifest.PageReference] = [], pages: [String: Data] = [:]
    var start = 0
    while start < count {
      let length = min(FileEvidenceLimits.chunksPerPage, count - start)
      let refs = (start..<(start + length)).map { index in
        let size = index == count - 1 ? Int(total - Int64(index) * Int64(FileEvidenceLimits.chunkBytes)) : FileEvidenceLimits.chunkBytes
        return chunk(size: size, epoch: mixedEpochs && !index.isMultiple(of: 2) ? 2 : 1)
      }
      let encoded = try FileEvidenceChunkPage(startIndex: start, chunks: refs).validateStructure().canonicalBytes
      let ref = BlobRef(digest: digest("page-cipher-\(start)"), plain: Canonical.digest(encoded), epoch: 3, size: encoded.count)
      descriptors.append(.init(startIndex: start, count: length, ref: ref)); pages[ref.plain] = encoded
      start += length
    }
    let root = FileEvidenceManifest(fileDigest: total == 0 ? FileEvidenceLimits.emptyFileDigest : digest("unverified file content \(total)"),
      totalBytes: total, chunkCount: count, pages: descriptors)
    return Fixture(root: root, pages: pages)
  }
  private func root(_ base: FileEvidenceManifest, total: Int64? = nil, count: Int? = nil,
    pages: [FileEvidenceManifest.PageReference]? = nil) -> FileEvidenceManifest {
    .init(fileDigest: base.fileDigest, totalBytes: total ?? base.totalBytes, chunkCount: count ?? base.chunkCount, pages: pages ?? base.pages)
  }
  private func singlePage(_ chunks: [BlobRef], total: Int64, pageStart: Int = 0, descriptorCount: Int? = nil) throws -> Fixture {
    let encoded = try FileEvidenceChunkPage(startIndex: pageStart, chunks: chunks).validateStructure().canonicalBytes
    let ref = BlobRef(digest: digest("single page cipher"), plain: Canonical.digest(encoded), epoch: 1, size: encoded.count)
    let manifest = FileEvidenceManifest(fileDigest: digest("claimed file hash"), totalBytes: total,
      chunkCount: total == 0 ? 0 : Int((total - 1) / Int64(FileEvidenceLimits.chunkBytes) + 1),
      pages: [.init(startIndex: 0, count: descriptorCount ?? chunks.count, ref: ref)])
    return Fixture(root: manifest, pages: [ref.plain: encoded])
  }

  @Test func boundarySizesIncluding64GiBValidateWithoutAllocatingFileContents() throws {
    let chunk = Int64(FileEvidenceLimits.chunkBytes)
    let totals: [Int64] = [0, 1, chunk - 1, chunk, chunk + 1, chunk * 128, chunk * 128 + 1, FileEvidenceLimits.fileBytes]
    for total in totals {
      let value = try fixture(total: total), structure = try value.root.validateStructure(), graph = try value.graph()
      let bytes = structure.canonicalBytes
      #expect(bytes.count <= FileEvidenceLimits.rootBytes)
      let decoded = try FileEvidenceManifest.decodeUntrusted(bytes)
      #expect(decoded == value.root)
      let sizes = graph.chunks.reduce(Int64(0)) { $0 + Int64($1.size) }
      #expect(sizes == total)
      #expect(graph.chunks.count == value.root.chunkCount)
      #expect(value.root.pages.count <= FileEvidenceLimits.pages)
    }
    let largest = try fixture(total: FileEvidenceLimits.fileBytes)
    #expect(largest.root.chunkCount == 65_536)
    #expect(largest.root.pages.count == 512)
  }

  @Test func emptyFileHasOneExplicitShapeAndNeverLoadsPages() throws {
    let empty = FileEvidenceManifest(fileDigest: FileEvidenceLimits.emptyFileDigest, totalBytes: 0, chunkCount: 0, pages: [])
    let structure = try empty.validateStructure()
    let graph = try structure.validateGraph { _ in Issue.record("Empty file must not load a page"); throw FileEvidenceManifestError.pageMismatch }
    #expect(graph.chunks.isEmpty)
    let falseEmpty = FileEvidenceManifest(fileDigest: digest("not empty"), totalBytes: 0, chunkCount: 0, pages: [])
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try falseEmpty.validateStructure() }
    let nonempty = try fixture(total: 1)
    let advertisedPage = root(nonempty.root, total: 0, count: 0)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try advertisedPage.validateStructure() }
  }

  @Test func decodingRemainsUntrustedAndRejectsUnsupportedKeysAndOversizedInput() throws {
    let valid = try fixture(total: 1), goodBytes = try valid.root.validateStructure().canonicalBytes
    let json: Any = try JSONSerialization.jsonObject(with: goodBytes)
    var object = try #require(json as? [String: Any])
    object["version"] = 2
    let unsupportedBytes = try JSONSerialization.data(withJSONObject: object)
    let untrusted = try FileEvidenceManifest.decodeUntrusted(unsupportedBytes)
    #expect(untrusted.version == 2)
    #expect(throws: FileEvidenceManifestError.unsupportedFormat) { try untrusted.validateStructure() }
    object["version"] = 1; object["unknownMeaning"] = "must not disappear"
    let extraKeyBytes = try JSONSerialization.data(withJSONObject: object)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try FileEvidenceManifest.decodeUntrusted(extraKeyBytes) }
    let oversizedRoot = Data(repeating: 0, count: FileEvidenceLimits.rootBytes + 1)
    let oversizedPage = Data(repeating: 0, count: FileEvidenceLimits.pageBytes + 1)
    #expect(throws: FileEvidenceManifestError.exceedsLimits) { try FileEvidenceManifest.decodeUntrusted(oversizedRoot) }
    #expect(throws: FileEvidenceManifestError.exceedsLimits) { try FileEvidenceChunkPage.decodeUntrusted(oversizedPage) }
    let page = try FileEvidenceChunkPage(startIndex: 0, chunks: [chunk(size: 1)]).validateStructure()
    let pageJSON: Any = try JSONSerialization.jsonObject(with: page.canonicalBytes)
    var pageObject = try #require(pageJSON as? [String: Any])
    var refs = try #require(pageObject["chunks"] as? [[String: Any]])
    refs[0]["foreignNamespace"] = "not part of BlobRef"
    pageObject["chunks"] = refs
    let foreignReferenceBytes = try JSONSerialization.data(withJSONObject: pageObject)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try FileEvidenceChunkPage.decodeUntrusted(foreignReferenceBytes) }
  }

  @Test func arithmeticAndRangeCorruptionThrowRatherThanOverflow() throws {
    let valid = try fixture(total: 1)
    let excessiveBytes = root(valid.root, total: Int64.max)
    let excessiveCount = root(valid.root, count: Int.max)
    let negativeBytes = root(valid.root, total: -1)
    #expect(throws: FileEvidenceManifestError.exceedsLimits) { try excessiveBytes.validateStructure() }
    #expect(throws: FileEvidenceManifestError.exceedsLimits) { try excessiveCount.validateStructure() }
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try negativeBytes.validateStructure() }
    let ref = try #require(valid.root.pages.first?.ref)
    for descriptor in [
      FileEvidenceManifest.PageReference(startIndex: Int.max, count: 1, ref: ref),
      .init(startIndex: 0, count: Int.max, ref: ref),
      .init(startIndex: -1, count: 1, ref: ref),
      .init(startIndex: 0, count: 0, ref: ref)] {
      let malformed = root(valid.root, pages: [descriptor])
      #expect(throws: FileEvidenceManifestError.invalidStructure) { try malformed.validateStructure() }
    }
    let impossibleStart = FileEvidenceChunkPage(startIndex: Int.max, chunks: [chunk(size: 1)])
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try impossibleStart.validateStructure() }
    let excessiveRefs = FileEvidenceChunkPage(startIndex: 0, chunks: Array(repeating: chunk(size: 1), count: 129))
    #expect(throws: FileEvidenceManifestError.exceedsLimits) { try excessiveRefs.validateStructure() }
    let excessivePages = root(valid.root, pages: Array(repeating: .init(startIndex: 0, count: 1, ref: ref), count: 513))
    #expect(throws: FileEvidenceManifestError.exceedsLimits) { try excessivePages.validateStructure() }
  }

  @Test func strictReferencesAllowMixedEpochsAndRepeatedContentButNotContradictions() throws {
    let total = Int64(FileEvidenceLimits.chunkBytes) * 3
    let value = try fixture(total: total, mixedEpochs: true), graph = try value.graph()
    #expect(graph.chunks[0].plain == graph.chunks[1].plain)
    #expect(graph.chunks[0].epoch != graph.chunks[1].epoch)
    #expect(graph.chunks[0] == graph.chunks[2])
    let good = chunk(size: 1)
    let invalid: [BlobRef] = [
      .init(digest: good.digest.uppercased(), plain: good.plain, epoch: 1, size: 1),
      .init(digest: good.digest, plain: "", epoch: 1, size: 1),
      .init(digest: good.digest, plain: good.plain, epoch: 0, size: 1),
      .init(digest: good.digest, plain: good.plain, epoch: -1, size: 1),
      .init(digest: good.digest, plain: good.plain, epoch: 1, size: 0),
      .init(digest: good.digest, plain: good.plain, epoch: 1, size: -1),
      .init(digest: good.digest, plain: good.plain, epoch: 1, size: FileEvidenceLimits.chunkBytes + 1)]
    for ref in invalid {
      let page = FileEvidenceChunkPage(startIndex: 0, chunks: [ref])
      #expect(throws: FileEvidenceManifestError.invalidReference) { try page.validateStructure() }
    }
    let contradictory = BlobRef(digest: good.digest, plain: digest("different plaintext"), epoch: 1, size: 1)
    let inconsistent = FileEvidenceChunkPage(startIndex: 0, chunks: [good, contradictory])
    #expect(throws: FileEvidenceManifestError.invalidReference) { try inconsistent.validateStructure() }
  }

  @Test func suppliedPageIntegrityAndContiguousGraphAreCheckedWithoutClaimingChunkContentVerification() throws {
    let value = try fixture(total: 1), structure = try value.root.validateStructure()
    #expect(throws: FileEvidenceManifestError.pageMismatch) { try structure.validateGraph { _ in Data("wrong page".utf8) } }
    let falseStart = try singlePage([chunk(size: 1)], total: 1, pageStart: 1)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try falseStart.graph() }
    let missingReference = root(value.root, pages: [])
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try missingReference.validateStructure() }
    let two = Int64(FileEvidenceLimits.chunkBytes) + 1
    let wrongFirstSize = try singlePage([chunk(size: 1), chunk(size: 1)], total: two)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try wrongFirstSize.graph() }
    let wrongFinalSize = try singlePage([chunk(size: FileEvidenceLimits.chunkBytes), chunk(size: 2)], total: two)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try wrongFinalSize.graph() }
    let wrongCount = try singlePage([chunk(size: 1)], total: two, descriptorCount: 2)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try wrongCount.graph() }
    let paged = try fixture(total: Int64(FileEvidenceLimits.chunkBytes) * 128 + 1)
    let first = try #require(paged.root.pages.first), second = try #require(paged.root.pages.last)
    let reordered = root(paged.root, pages: [second, first])
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try reordered.validateStructure() }
    let gap = FileEvidenceManifest.PageReference(startIndex: second.startIndex + 1, count: second.count, ref: second.ref)
    let overlap = FileEvidenceManifest.PageReference(startIndex: second.startIndex - 1, count: second.count, ref: second.ref)
    for malformed in [gap, overlap] {
      let wrongRange = root(paged.root, pages: [first, malformed])
      #expect(throws: FileEvidenceManifestError.invalidStructure) { try wrongRange.validateStructure() }
    }
    let swappedPageBytes = FileEvidenceManifest.PageReference(startIndex: first.startIndex, count: first.count, ref: second.ref)
    let wrongPage = Fixture(root: root(paged.root, pages: [swappedPageBytes, second]), pages: paged.pages)
    #expect(throws: FileEvidenceManifestError.invalidStructure) { try wrongPage.graph() }
    let graph = try value.graph()
    // No chunk or file bytes were supplied: this remains a bounded reference graph only.
    #expect(graph.root.fileDigest == value.root.fileDigest)
    #expect(graph.chunks.count == 1)
  }
}
