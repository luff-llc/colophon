import Foundation

/// A library-scoped pointer, never a transport for private note text or access credentials.
/// Custom schemes are app routing hints; the receiver must resolve the signed source.
public struct PodcastNoteLink: Sendable, Hashable {
  public enum Destination: Sendable, Hashable {
    case writing
    case moment(episode: String, seconds: Double)
  }

  public let libraryID: String
  public let noteID: String
  public let revision: String
  public let destination: Destination

  public init?(libraryID: String, noteID: String, revision: String, destination: Destination = .writing) {
    guard [libraryID, noteID, revision].allSatisfy(Self.validID) else { return nil }
    if case .moment(let episode, let seconds) = destination {
      guard Self.validID(episode), seconds.isFinite, seconds >= 0, seconds <= 31_536_000 else { return nil }
    }
    self.libraryID = libraryID; self.noteID = noteID; self.revision = revision; self.destination = destination
  }

  public init?(url: URL) {
    guard url.absoluteString.utf8.count <= 8_192,
      let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
      parts.user == nil, parts.password == nil, parts.port == nil, parts.fragment == nil,
      let items = parts.queryItems,
      Set(items.map(\.name)).count == items.count,
      items.allSatisfy({ $0.value != nil }) else { return nil }
    let values = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
    guard let library = values["library"], let note = values["note"], let revision = values["revision"] else { return nil }
    let destination: Destination
    switch (parts.scheme?.lowercased(), parts.host?.lowercased()) {
    case ("scribenda", "continue"):
      guard parts.path.isEmpty, Set(values.keys) == Set(["library", "note", "revision"]) else { return nil }
      destination = .writing
    case ("taupe", "moment"):
      guard Set(values.keys) == Set(["library", "note", "revision", "t"]),
        parts.percentEncodedPath.hasPrefix("/"),
        let episode = String(parts.percentEncodedPath.dropFirst()).removingPercentEncoding,
        let raw = values["t"], let seconds = Double(raw), seconds.isFinite, seconds >= 0 else { return nil }
      destination = .moment(episode: episode, seconds: seconds)
    default: return nil
    }
    self.init(libraryID: library, noteID: note, revision: revision, destination: destination)
  }

  public var url: URL? {
    var parts = URLComponents()
    parts.queryItems = [URLQueryItem(name: "library", value: libraryID), URLQueryItem(name: "note", value: noteID),
      URLQueryItem(name: "revision", value: revision)]
    switch destination {
    case .writing:
      parts.scheme = "scribenda"; parts.host = "continue"
    case .moment(let episode, let seconds):
      parts.scheme = "taupe"; parts.host = "moment"
      let safe = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
      guard let path = episode.addingPercentEncoding(withAllowedCharacters: safe) else { return nil }
      parts.percentEncodedPath = "/" + path
      parts.queryItems?.append(URLQueryItem(name: "t", value: String(seconds)))
    }
    return parts.url
  }

  private static func validID(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 512 && !value.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
  }
}
