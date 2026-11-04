import Foundation
import Testing
@testable import ColophonCore

struct PrivateAtomicFileTests {
  private enum Injected: Error { case stop }

  private func folder() throws -> URL {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent("private-atomic-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
    return path
  }

  private func permissions(_ url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
  }

  @Test func privateStageAndPayloadPrecedePublication() throws {
    let root = try folder()
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("identity.json")
    let bytes = Data("private identity bytes".utf8)
    var reached = false
    try PrivateAtomicFile.write(bytes, to: target) { payload in
      reached = true
      let stagePermissions = try permissions(payload.deletingLastPathComponent())
      let payloadPermissions = try permissions(payload)
      #expect(stagePermissions == 0o700)
      #expect(payloadPermissions == 0o600)
      #expect(!FileManager.default.fileExists(atPath: target.path))
      let staged = try Data(contentsOf: payload)
      #expect(staged == bytes)
      #if os(iOS) || os(visionOS)
      let protection = try FileManager.default.attributesOfItem(atPath: payload.path)[.protectionKey] as? FileProtectionType
      #expect(protection == .complete)
      #endif
    }
    #expect(reached)
    let published = try Data(contentsOf: target)
    let finalPermissions = try permissions(target)
    let entries = try FileManager.default.contentsOfDirectory(atPath: root.path)
    #expect(published == bytes)
    #expect(finalPermissions == 0o600)
    #expect(entries.count == 1)
  }

  @Test func injectedFailurePreservesExistingTargetAndCleansStage() throws {
    let root = try folder()
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("state.json")
    let old = Data("old state".utf8)
    try old.write(to: target)
    #expect(throws: Injected.self) {
      try PrivateAtomicFile.write(Data("new state".utf8), to: target) { _ in throw Injected.stop }
    }
    let retained = try Data(contentsOf: target)
    let entries = try FileManager.default.contentsOfDirectory(atPath: root.path)
    #expect(retained == old)
    #expect(entries.count == 1)
  }

  @Test func failedNewWriteLeavesNoDestinationOrPartials() throws {
    let root = try folder()
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("new.json")
    #expect(throws: Injected.self) {
      try PrivateAtomicFile.write(Data("new".utf8), to: target) { _ in throw Injected.stop }
    }
    let entries = try FileManager.default.contentsOfDirectory(atPath: root.path)
    #expect(entries.isEmpty)
  }

  @Test func successfulReplacementKeepsPrivatePermissions() throws {
    let root = try folder()
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("settings.json")
    try Data("old".utf8).write(to: target)
    let replacement = Data("replacement".utf8)
    try PrivateAtomicFile.write(replacement, to: target)
    let actual = try Data(contentsOf: target)
    let mode = try permissions(target)
    #expect(actual == replacement)
    #expect(mode == 0o600)
  }

  @Test func missingParentIsNotCreated() throws {
    let root = try folder()
    defer { try? FileManager.default.removeItem(at: root) }
    let missing = root.appendingPathComponent("missing", isDirectory: true)
    #expect(throws: NSError.self) {
      try PrivateAtomicFile.write(Data("new".utf8), to: missing.appendingPathComponent("state"))
    }
    let entries = try FileManager.default.contentsOfDirectory(atPath: root.path)
    #expect(entries.isEmpty)
  }

  @Test func destinationSymlinkIsReplacedWithoutChangingItsReferent() throws {
    let root = try folder()
    defer { try? FileManager.default.removeItem(at: root) }
    let referent = root.appendingPathComponent("referent")
    let target = root.appendingPathComponent("target")
    let original = Data("preserved referent".utf8)
    try original.write(to: referent)
    try FileManager.default.createSymbolicLink(at: target, withDestinationURL: referent)
    let replacement = Data("private replacement".utf8)
    try PrivateAtomicFile.write(replacement, to: target)
    let referred = try Data(contentsOf: referent)
    let actual = try Data(contentsOf: target)
    let values = try target.resourceValues(forKeys: [.isSymbolicLinkKey])
    #expect(referred == original)
    #expect(actual == replacement)
    #expect(values.isSymbolicLink == false)
  }
}
