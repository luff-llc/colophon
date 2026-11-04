import Darwin
import Foundation

struct FileUbiquitySource: UbiquitySource {
  let download: @Sendable (URL) throws -> Void
  let metadata: UbiquityDownloadMetadata

  func requestDownload(of file: URL) throws { try download(file) }

  func transferProgress(of file: URL) -> UbiquityTransferProgress? { metadata.progress(of: file) }

  func availability(of file: URL) throws -> UbiquitousItemAvailability {
    let name = file.lastPathComponent
    guard !name.isEmpty, name != ".", name != ".." else { return .absent }
    let realPath = file.path(percentEncoded: false)
    var info = Darwin.stat()
    if realPath.withCString({ lstat($0, &info) }) != 0 {
      let failure = errno
      guard failure == ENOENT || failure == ENOTDIR else {
        throw POSIXError(POSIXErrorCode(rawValue: failure) ?? .EIO)
      }
      let placeholder = file.deletingLastPathComponent().appending(path: "." + name + ".icloud")
      var placeholderInfo = Darwin.stat()
      if placeholder.path(percentEncoded: false).withCString({ lstat($0, &placeholderInfo) }) == 0 {
        if realPath.contains("/Mobile Documents/") { metadata.start() }
        return .pending
      }
      let placeholderFailure = errno
      guard placeholderFailure == ENOENT || placeholderFailure == ENOTDIR else {
        throw POSIXError(POSIXErrorCode(rawValue: placeholderFailure) ?? .EIO)
      }
      return .absent
    }
    // A dataless file can live outside the standard Mobile Documents location too.
    if (UInt32(info.st_flags) & 0x40000000) != 0 {
      if realPath.contains("/Mobile Documents/") { metadata.start() }
      else if (try? file.resourceValues(forKeys: [.isUbiquitousItemKey]))?.isUbiquitousItem == true { metadata.start() }
      return .pending
    }
    // Ordinary local records retain their lstat-only fast path.
    guard realPath.contains("/Mobile Documents/") else { return .downloaded }
    let values = try file.resourceValues(forKeys: [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey])
    if values.isUbiquitousItem == true, values.ubiquitousItemDownloadingStatus == .notDownloaded {
      metadata.start()
      return .pending
    }
    return .downloaded
  }
}
