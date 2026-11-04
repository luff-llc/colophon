import CryptoTokenKit
import Foundation
import Testing
@testable import ColophonCore

struct DeviceIdentityAvailabilityTests {
  private enum CreationAttempted: Error { case forbidden }
  @Test func tokenFailureNeverReplacesAnExistingIdentity() throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "invalidated-identity-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appending(path: "identity.json")
    let bytes = try Canonical.encode(DeviceIdentity.software(SoftwareIdentity()))
    try bytes.write(to: url)
    do {
      _ = try DeviceIdentity.loadOrCreate(at: url, requiresPresence: false,
        readData: { _ in throw NSError(domain: TKErrorDomain, code: -10) },
        createIdentity: { _ in throw CreationAttempted.forbidden })
      Issue.record("Invalidated identity reads must not replace the identity")
    } catch {
      #expect(DeviceKeyFailure(error) == .invalidated)
    }
    let after = try Data(contentsOf: url)
    #expect(after == bytes)
  }

  @Test func unreadableExistingIdentityIsNeverRecreated() throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "identity-availability-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appending(path: "identity.json")
    let bytes = try Canonical.encode(DeviceIdentity.software(SoftwareIdentity()))
    try bytes.write(to: url)
    #expect(throws: CocoaError.self) {
      try DeviceIdentity.loadOrCreate(at: url, requiresPresence: false,
        readData: { _ in throw CocoaError(.fileReadNoPermission) },
        createIdentity: { _ in throw CreationAttempted.forbidden })
    }
    let after = try Data(contentsOf: url)
    #expect(after == bytes)
  }

  @Test func newIdentityIsLeftOutOfBackups() throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "identity-backup-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appending(path: "identity.json")
    _ = try DeviceIdentity.loadOrCreate(at: url, requiresPresence: false, readData: { try Data(contentsOf: $0) },
      createIdentity: { _ in .software(SoftwareIdentity()) })
    let excluded = try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
    #expect(excluded == true)
  }

  @Test func existingIdentityIsMovedOutOfBackupsWithoutChanging() throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "identity-backup-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let url = directory.appending(path: "identity.json")
    let bytes = try Canonical.encode(DeviceIdentity.software(SoftwareIdentity()))
    try bytes.write(to: url)
    _ = try DeviceIdentity.loadOrCreate(at: url, requiresPresence: false, readData: { try Data(contentsOf: $0) },
      createIdentity: { _ in throw CreationAttempted.forbidden })
    let excluded = try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
    #expect(excluded == true)
    let after = try Data(contentsOf: url)
    #expect(after == bytes)
  }
}
