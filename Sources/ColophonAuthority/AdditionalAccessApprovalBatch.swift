import ColophonCore
import Foundation

/// Exact already-signed grant/share tail. No plaintext namespace key or signing secret is journaled.
public struct AdditionalAccessApprovalBatch: Codable, Sendable {
  public static let format = "org.colophon.additional-access-approval"
  public static let maximumBytes = 16_777_216
  public let format: String
  public let version: Int
  public let id: String
  public let libraryID: String
  public let memberID: String
  public let requestID: UUID
  public let requestBodyDigest: String
  public let request: SignedRecord
  public let selectedNamespaces: [String]
  public let baseSequence: Int
  public let baseDigest: String
  public let records: [SignedRecord]
  init(prepared: PreparedAdditionalAccessApproval, records: [SignedRecord]) throws {
    try Self.validateBoundedRecords(records)
    format = Self.format; version = 1; libraryID = prepared.request.request.libraryID
    memberID = prepared.request.request.member.id; requestID = prepared.request.request.requestID
    requestBodyDigest = prepared.request.bodyDigest; request = prepared.request.signed
    selectedNamespaces = prepared.selectedNamespaces; baseSequence = prepared.baseSequence; baseDigest = prepared.baseDigest
    self.records = records
    id = try Self.identity(records: records, request: requestBodyDigest, base: baseDigest)
  }
  func validatedRequest() throws -> AdditionalAccessRequest.Record {
    guard format == Self.format, version == 1, baseSequence > 0,
      !libraryID.isEmpty, libraryID.utf8.count <= 1024, memberID.utf8.count == 32,
      Self.isDigest(id), Self.isDigest(requestBodyDigest), Self.isDigest(baseDigest),
      !selectedNamespaces.isEmpty, selectedNamespaces.count <= 64,
      selectedNamespaces == Array(Set(selectedNamespaces)).sorted() else { throw AdditionalAccessError.journalConflict }
    try Self.validateBoundedRecords(records)
    try Self.validateBoundedRecords([request])
    guard id == (try Self.identity(records: records, request: requestBodyDigest, base: baseDigest)) else { throw AdditionalAccessError.journalConflict }
    let record = try AdditionalAccessRequest.Record.decode(Canonical.encode(request), path: AdditionalAccessRequest.path(memberID: memberID))
    guard record.bodyDigest == requestBodyDigest, record.request.libraryID == libraryID,
      record.request.requestID == requestID,
      selectedNamespaces.allSatisfy({ record.request.additionalNamespaces.contains($0) }) else { throw AdditionalAccessError.journalConflict }
    return record
  }
  private static func isDigest(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }
  static func validateBoundedRecords(_ records: [SignedRecord]) throws {
    guard !records.isEmpty, records.count <= AdditionalAccessApprovalBuilder.maximumRecords else { throw AdditionalAccessError.exceedsLimits }
    // Conservative JSON upper bound before Canonical.encode: base64 may escape every slash,
    // strings may expand to six bytes per UTF-8 byte, and every record has framing overhead.
    var encodedBudget = 4096
    func charge(_ amount: Int) throws {
      guard amount <= Self.maximumBytes - encodedBudget else { throw AdditionalAccessError.exceedsLimits }
      encodedBudget += amount
    }
    func include(_ data: Data, maximum: Int) throws {
      guard data.count <= maximum else { throw AdditionalAccessError.exceedsLimits }
      try charge(((data.count + 2) / 3) * 8 + 16)
    }
    func assertion(_ value: Assertion?) throws {
      guard let value else { return }
      try charge(128)
      try include(value.authenticatorData, maximum: 65_536); try include(value.clientData, maximum: 65_536)
    }
    for record in records {
      try charge(256)
      try include(record.body, maximum: AdditionalAccessRequest.maximumBodyBytes)
      try include(record.signature, maximum: 512); try assertion(record.assertion)
      let extra = record.cosignatures ?? []
      guard extra.count <= 64 else { throw AdditionalAccessError.exceedsLimits }
      for signature in extra {
        guard signature.signer.utf8.count <= 1024 else { throw AdditionalAccessError.exceedsLimits }
        try charge(signature.signer.utf8.count * 6 + 256)
        try include(signature.signature, maximum: 512); try assertion(signature.assertion)
      }
    }
  }

  static func identity(records: [SignedRecord], request: String, base: String) throws -> String {
    Canonical.digest(Data("colophon.additional-approval.v1\0".utf8) + Data(request.utf8) + Data([0]) + Data(base.utf8) + Data([0]) + (try Canonical.encode(records)))
  }
}
