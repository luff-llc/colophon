import ColophonCore
import Foundation

/// A remote copy of a library, reached asynchronously (spec §5.2).
public protocol RemoteStore: Sendable {
  func list(_ directory: String) async throws -> [String]
  func read(_ path: String) async throws -> Data?
  /// Creates a record; must not overwrite. Returns false if it already existed.
  @discardableResult func create(_ path: String, _ data: Data) async throws -> Bool
  func replace(_ path: String, _ data: Data) async throws
}

/// Copies records between a local store and a remote one. Clients always read and write the local
/// store, so they work offline; syncing is a separate step whenever the network allows.
///
/// Immutable records are copied in both directions and never overwritten. Requests are mutable and
/// the requester's own copy wins. Nothing is decrypted or interpreted.
public struct StoreSync: Sendable {
  public let local: any RecordStore
  public let remote: any RemoteStore

  public init(local: any RecordStore, remote: any RemoteStore) {
    self.local = local
    self.remote = remote
  }

  public struct Report: Sendable, Equatable {
    public var pulled = 0
    public var pushed = 0
  }

  @discardableResult
  public func run() async throws -> Report {
    var report = Report()
    try await authority(&report)
    for author in Set(try local.list(LibraryPath.operations) + (try await remote.list(LibraryPath.operations))) {
      try await mirror(LibraryPath.operations + "/" + author, &report)
    }
    try await mirror(LibraryPath.blobs, &report)
    try await requests(&report)
    return report
  }

  /// Authority entries are numbered; copy forward from whichever side is ahead.
  private func authority(_ report: inout Report) async throws {
    var seq = 1
    while true {
      let path = LibraryPath.authority(seq)
      let here = try local.read(path)
      let there = here == nil ? try await remote.read(path) : nil
      if let here {
        if try await remote.create(path, here) { report.pushed += 1 }
      } else if let there {
        try local.create(path, there)
        report.pulled += 1
      } else {
        return
      }
      seq += 1
    }
  }

  private func mirror(_ directory: String, _ report: inout Report) async throws {
    let here = Set(try local.list(directory))
    let there = Set(try await remote.list(directory))
    for name in there.subtracting(here) {
      if let data = try await remote.read(directory + "/" + name) {
        try local.create(directory + "/" + name, data)
        report.pulled += 1
      }
    }
    for name in here.subtracting(there) {
      if let data = try local.read(directory + "/" + name), try await remote.create(directory + "/" + name, data) {
        report.pushed += 1
      }
    }
  }

  private func requests(_ report: inout Report) async throws {
    let here = Set(try local.list(LibraryPath.requests))
    for name in Set(try await remote.list(LibraryPath.requests)).subtracting(here) {
      if let data = try await remote.read(LibraryPath.requests + "/" + name) {
        try local.replace(LibraryPath.requests + "/" + name, data)
        report.pulled += 1
      }
    }
    for name in here {
      if let data = try local.read(LibraryPath.requests + "/" + name) {
        try await remote.replace(LibraryPath.requests + "/" + name, data)
      }
    }
  }
}
