import ColophonCore
import ColophonReplica
import Foundation

/// Shape validation also runs while folding, because replicas can receive commands from old
/// or independent writers that bypass adapter validation.
internal enum NotesContentValidation {
  static func id(_ value: String?) -> Bool {
    guard let value else { return false }
    return !value.isEmpty && value.utf8.count <= 512 && !value.contains(where: { $0.isNewline || $0.asciiValue == 0 })
  }

  static func optionalString(_ p: [String: JSONValue], _ key: String, max: Int) -> Bool {
    guard let value = p[key], value != .null else { return true }
    guard let text = value.string else { return false }
    return text.utf8.count <= max
  }

  static func tags(_ p: [String: JSONValue]) -> [String]? {
    guard let raw = p["tags"], raw != .null else { return [] }
    guard let array = raw.array, array.count <= 64 else { return nil }
    let values = array.compactMap(\.string)
    guard values.count == array.count, values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 }),
      Set(values).count == values.count else { return nil }
    return values
  }

  static func valid(_ kind: String, _ p: [String: JSONValue]) -> Bool {
    guard id(p["notebook"]?.string) else { return false }
    if let entry = p["entry"], entry != .null, !id(entry.string) { return false }
    switch kind {
    case Notes.Kind.putEntry:
      guard id(p["entry"]?.string), optionalString(p, "title", max: 512), tags(p) != nil,
        optionalString(p, "expect", max: 512), optionalString(p, "date", max: 10) else { return false }
      if let date = p["date"]?.string {
        let parts = date.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
          let year = Int(parts[0]), let month = Int(parts[1]), let day = Int(parts[2]),
          year > 0, (1...12).contains(month), (1...31).contains(day) else { return false }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .gmt
        let components = DateComponents(year: year, month: month, day: day)
        guard let value = calendar.date(from: components), calendar.dateComponents([.year, .month, .day], from: value) == components else { return false }
      }
      return true
    case Notes.Kind.attach:
      guard id(p["attachment"]?.string), id(p["name"]?.string),
        p["role"]?.string.flatMap(NotesAttachment.Role.init(rawValue:)) != nil,
        optionalString(p, "mime", max: 256) else { return false }
      let hasBlob = p["blob"] != nil && p["blob"] != .null
      let hasSource = p["source"] != nil && p["source"] != .null
      guard hasBlob != hasSource else { return false }
      if hasBlob {
        guard let blob = BlobRef(json: p["blob"]), digest(blob.digest), digest(blob.plain), blob.epoch > 0,
          blob.size >= 0, blob.size <= 536_870_912 else { return false }
        return true
      }
      return source(p["source"]) != nil
    case Notes.Kind.propose:
      guard id(p["entry"]?.string), id(p["proposal"]?.string), optionalString(p, "title", max: 512),
        tags(p) != nil, let markdown = p["markdown"]?.string, markdown.utf8.count <= 16_384,
        let inputs = p["inputs"]?.object, inputs.count <= 2_048,
        inputs.allSatisfy({ id($0.key) && id($0.value.string) }) else { return false }
      return true
    case Notes.Kind.reviewProposal:
      return id(p["proposal"]?.string) && p["keep"]?.bool != nil && optionalString(p, "markdown", max: 16_384)
    default:
      return true
    }
  }

  static func digest(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }

  static func source(_ value: JSONValue?) -> NotesAttachment.SourceReference? {
    guard let p = value?.object else { return nil }
    switch p["kind"]?.string {
    case "web":
      guard let raw = p["url"]?.string, raw.utf8.count <= 4_096, let url = URL(string: raw),
        let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme),
        url.host?.isEmpty == false, url.user == nil, url.password == nil,
        ["library", "namespace", "artifact", "revision", "quote", "page", "seconds", "recording"].allSatisfy({ p[$0] == nil || p[$0] == .null })
      else { return nil }
      return .init(url: raw)
    case "library":
      guard id(p["library"]?.string), id(p["namespace"]?.string), id(p["artifact"]?.string), id(p["revision"]?.string),
        optionalString(p, "quote", max: 16_384), p["url"] == nil || p["url"] == .null else { return nil }
      if let page = p["page"], page != .null, !(page.int.map { $0 >= 0 } ?? false) { return nil }
      if let seconds = p["seconds"], seconds != .null {
        guard let time = seconds.double, time.isFinite, time >= 0,
          let recording = p["recording"]?.string, digest(recording) else { return nil }
      }
      if let recording = p["recording"], recording != .null, !(recording.string.map(digest) ?? false) { return nil }
      guard let library = p["library"]?.string, let namespace = p["namespace"]?.string,
        let artifact = p["artifact"]?.string, let revision = p["revision"]?.string else { return nil }
      return .init(libraryID: library, namespace: namespace, artifactID: artifact, revision: revision,
        quote: p["quote"]?.string, page: p["page"]?.int, seconds: p["seconds"]?.double,
        recordingDigest: p["recording"]?.string)
    default:
      return nil
    }
  }
}
