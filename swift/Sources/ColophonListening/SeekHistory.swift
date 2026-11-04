import Foundation

/// A bounded, device-local convenience history. It is not part of the signed library log and
/// does not synchronize. Each entry remembers the position before one intentional jump.
public struct SeekHistory: Codable, Sendable {
  public enum Reason: String, Codable, Sendable {
    case scrub, skip, chapter, citation
  }

  public struct Key: Hashable, Codable, Sendable {
    public let library: String
    public let episode: String
    public let audio: String

    public init(library: String, episode: String, audio: String) {
      self.library = library
      self.episode = episode
      self.audio = audio
    }
  }

  public struct Entry: Identifiable, Codable, Sendable {
    public let id: UUID
    public let origin: Double
    public let destination: Double
    public let reason: Reason
    /// The signed position operation that this device wrote for the jump.
    public var positionRevision: String?

    public init(id: UUID = UUID(), origin: Double, destination: Double, reason: Reason,
      positionRevision: String? = nil)
    {
      self.id = id
      self.origin = origin
      self.destination = destination
      self.reason = reason
      self.positionRevision = positionRevision
    }
  }

  private struct Bucket: Codable, Sendable {
    var key: Key
    var entries: [Entry]
  }

  private var buckets: [Bucket] = []
  public static let maxEntriesPerEpisode = 12
  public static let maxEpisodes = 50

  public init() {}

  public init(contentsOf url: URL) {
    self = (try? JSONDecoder().decode(Self.self, from: Data(contentsOf: url))) ?? Self()
    normalize()
  }

  public func save(to url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try JSONEncoder().encode(self).write(to: url, options: .atomic)
  }

  public func latest(for key: Key) -> Entry? {
    buckets.first { $0.key == key }?.entries.last
  }

  public func count(for key: Key) -> Int {
    buckets.first { $0.key == key }?.entries.count ?? 0
  }

  @discardableResult public mutating func append(_ entry: Entry, for key: Key) -> Bool {
    guard !key.library.isEmpty, !key.episode.isEmpty, !key.audio.isEmpty,
      entry.origin.isFinite, entry.destination.isFinite,
      entry.origin >= 0, entry.destination >= 0,
      abs(entry.origin - entry.destination) >= 0.5
    else { return false }
    var entries = buckets.first { $0.key == key }?.entries ?? []
    entries.append(entry)
    buckets.removeAll { $0.key == key }
    buckets.append(Bucket(key: key, entries: Array(entries.suffix(Self.maxEntriesPerEpisode))))
    if buckets.count > Self.maxEpisodes { buckets.removeFirst(buckets.count - Self.maxEpisodes) }
    return true
  }

  @discardableResult public mutating func pop(for key: Key) -> Entry? {
    guard let index = buckets.firstIndex(where: { $0.key == key }) else { return nil }
    let entry = buckets[index].entries.popLast()
    if buckets[index].entries.isEmpty { buckets.remove(at: index) }
    return entry
  }

  public mutating func setRevision(_ revision: String, for id: UUID, key: Key) {
    guard let bucket = buckets.firstIndex(where: { $0.key == key }),
      let entry = buckets[bucket].entries.firstIndex(where: { $0.id == id })
    else { return }
    buckets[bucket].entries[entry].positionRevision = revision
  }

  public mutating func clear(for key: Key) { buckets.removeAll { $0.key == key } }

  /// Promotes provisional file metadata identity to a verified recording digest.
  public mutating func move(from old: Key, to new: Key) {
    guard old != new, let index = buckets.firstIndex(where: { $0.key == old }) else { return }
    let provisional = buckets.remove(at: index).entries
    // A jump made before hashing cannot prove that an older digest bucket's revision is
    // still its predecessor. Keep the provisional chain and discard that older chain.
    buckets.removeAll { $0.key == new }
    buckets.append(Bucket(key: new, entries: Array(provisional.suffix(Self.maxEntriesPerEpisode))))
    if buckets.count > Self.maxEpisodes { buckets.removeFirst(buckets.count - Self.maxEpisodes) }
  }

  private mutating func normalize() {
    buckets = Array(buckets.suffix(Self.maxEpisodes))
    for index in buckets.indices {
      buckets[index].entries = Array(buckets[index].entries.filter {
        $0.origin.isFinite && $0.destination.isFinite && $0.origin >= 0 && $0.destination >= 0
      }.suffix(Self.maxEntriesPerEpisode))
    }
    buckets.removeAll { $0.entries.isEmpty || $0.key.library.isEmpty || $0.key.episode.isEmpty || $0.key.audio.isEmpty }
  }
}
