import Foundation

public struct SupportReport: Codable, Sendable {
  public struct Application: Codable, Sendable {
    public let bundleIdentifier: String
    public let version: String
    public let build: String
    public let operatingSystem: String

    public init(bundle: Bundle = .main) {
      bundleIdentifier = bundle.bundleIdentifier ?? "unknown"
      version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
      build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
      operatingSystem = ProcessInfo.processInfo.operatingSystemVersionString
    }
  }
  public let formatVersion: Int
  public let generatedAt: Date
  public let application: Application
  public let logStorageAvailable: Bool
  public let context: SupportContext?
  public private(set) var events: [SupportEvent]

  public init(application: Application, events: [SupportEvent], logStorageAvailable: Bool, context: SupportContext? = nil) {
    formatVersion = 1; generatedAt = Date(); self.application = application
    self.events = events; self.logStorageAvailable = logStorageAvailable; self.context = context
  }

  public func json() throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    var bounded = self
    var data = try encoder.encode(bounded)
    while data.count > SupportLogStore.maximumBytes, !bounded.events.isEmpty {
      bounded.events.removeFirst(); data = try encoder.encode(bounded)
    }
    guard data.count <= SupportLogStore.maximumBytes else { throw CocoaError(.fileWriteOutOfSpace) }
    return data
  }
}
