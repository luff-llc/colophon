import ColophonCore
import ColophonListening
import ColophonReplica
import Foundation

/// A provisional agent-facing extension of the installed Colophon CLI. It uses the same
/// enrolled identity and Replica as the other commands. This does not add an MCP tool or
/// standardize a new domain schema, and the CLI deliberately has no acceptance command.
enum SharedTranscriptCommand {
  private struct ReadInput: Decodable {
    let reference: SharedTranscriptReference
  }

  private struct VerifyInput: Decodable {
    let reference: SharedTranscriptReference
    let quote: String
  }

  private struct VerifyOutput: Encodable {
    let reference: SharedTranscriptReference
    let namespace: String
    let quote: String
    let verifiedBy: String
    let observedAt: Date
    let verification: String
    let provisional: Bool
  }

  private struct ProposeInput: Decodable {
    let reference: SharedTranscriptReference
    let quote: String
    let text: String
    let contributionID: String
    let commandID: String
    let expectedRevision: String?
  }

  private struct ListOutput: Encodable {
    let references: [SharedTranscriptReference]
  }

  private struct ReadOutput: Encodable {
    let reference: SharedTranscriptReference
    let transcript: TranscriptDocument
    let state: SharedTranscriptState
  }

  private struct ProposeOutput: Encodable {
    let receipt: SharedTranscriptReceipt
    let state: SharedTranscriptState
  }

  static func run(_ action: String, replica: Replica) throws {
    let service = SharedTranscriptService(replica: replica)
    switch action {
    case "list":
      try printJSON(ListOutput(references: service.references()))
    case "read":
      let request = try input(ReadInput.self)
      let transcript = try service.resolve(request.reference)
      let state = try service.state(for: request.reference)
      try printJSON(ReadOutput(reference: request.reference, transcript: transcript, state: state))
    case "verify":
      let request = try input(VerifyInput.self)
      _ = try service.resolve(request.reference, citation: .init(quote: request.quote))
      try printJSON(VerifyOutput(reference: request.reference, namespace: Podcasts.namespace,
        quote: request.quote, verifiedBy: replica.identity.id, observedAt: .now,
        verification: "verified", provisional: true))
    case "propose":
      let request = try input(ProposeInput.self)
      let receipt = try service.propose(reference: request.reference, citation: .init(quote: request.quote),
        text: request.text, contributionID: request.contributionID, commandID: request.commandID,
        expectedRevision: request.expectedRevision)
      let state = try service.state(for: request.reference)
      try printJSON(ProposeOutput(receipt: receipt, state: state))
    case "capture-verify":
      let request = try input(CaptureThoughtVerifyInput.self)
      let bundle = try CaptureThoughtVerifier(replica: replica).verify(request)
      let encoded = try Canonical.encode(bundle)
      guard encoded.count <= 64 * 1_024 else {
        throw ColophonError.malformed("Verified capture bundle exceeds 64 KiB")
      }
      FileHandle.standardOutput.write(encoded + Data("\n".utf8))
    default:
      throw ColophonError.malformed("Context action must be list, read, verify, propose, or capture-verify")
    }
  }

  private static func input<T: Decodable>(_ type: T.Type) throws -> T {
    // Bound requests before decoding, including when fed by a producer outside this process.
    let maximumInputBytes = 64 * 1_024
    var data = Data()
    while true {
      let remainingPlusOne = maximumInputBytes - data.count + 1
      let chunk = try FileHandle.standardInput.read(upToCount: min(16 * 1_024, remainingPlusOne)) ?? Data()
      if chunk.isEmpty { break }
      data.append(chunk)
      guard data.count <= maximumInputBytes else { throw ColophonError.malformed("Context request exceeds 64 KiB") }
    }
    guard !data.isEmpty else { throw ColophonError.malformed("Expected one JSON request on stdin") }
    // Foundation's full JSON parse rejects a valid prefix followed by a second object or garbage.
    _ = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    return try Canonical.decode(type, from: data)
  }

  private static func printJSON(_ value: some Encodable) throws {
    FileHandle.standardOutput.write(try Canonical.encode(value) + Data("\n".utf8))
  }
}
