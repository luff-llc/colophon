import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import Foundation

/// A poll/return adapter for an enrolled executor. Run this in a trusted host process and
/// pass only packet JSON to the model runtime. Do not give the model the identity or folder.
enum TranscriptQuestionCommand {
  private struct PacketInput: Decodable { let requestRevision: String }
  private struct ResponseInput: Decodable {
    let requestRevision: String
    let claims: [TranscriptAnswerClaim]
    let commandID: String
  }
  private struct Pending: Encodable {
    let requestRevision: String
    let question: String
    let expires: Date
    let status: String
  }
  private struct PendingOutput: Encodable { let requests: [Pending] }
  private struct ResponseOutput: Encodable {
    let revision: String
    let requestRevision: String
    let agentID: String
    let agentLabel: String
    let claims: [TranscriptAnswerClaim]
    let status: String
  }

  static func run(_ action: String, replica: Replica) throws {
    let service = TranscriptQuestionService(replica: replica)
    switch action {
    case "pending":
      guard let member = try replica.authority().members[replica.identity.id], member.role == .agent else {
        throw TranscriptQuestionError.wrongRole
      }
      let jobs = try service.states().filter {
        $0.request.targetAgentID == replica.identity.id && [.queued, .sourcePending].contains($0.status)
      }
      try output(PendingOutput(requests: jobs.map { Pending(requestRevision: $0.id, question: $0.request.question, expires: $0.request.expires, status: $0.status.rawValue) }))
    case "packet":
      let request = try input(PacketInput.self)
      try output(service.packet(requestRevision: request.requestRevision))
    case "respond":
      let input = try input(ResponseInput.self)
      let response = try service.respond(requestRevision: input.requestRevision, claims: input.claims,
        commandID: input.commandID)
      try output(ResponseOutput(revision: response.id, requestRevision: response.requestRevision,
        agentID: response.agentID, agentLabel: response.agentLabel, claims: response.claims,
        status: "awaitingReview"))
    default:
      throw ColophonError.malformed("Questions action must be pending, packet, or respond")
    }
  }

  private static func input<T: Decodable>(_ type: T.Type) throws -> T {
    let maximum = 256 * 1_024
    var data = Data()
    while true {
      let next = try FileHandle.standardInput.read(upToCount: min(16 * 1_024, maximum - data.count + 1)) ?? Data()
      if next.isEmpty { break }
      data.append(next)
      guard data.count <= maximum else { throw ColophonError.malformed("Question request exceeds 256 KiB") }
    }
    guard !data.isEmpty else { throw ColophonError.malformed("Expected one JSON request on stdin") }
    _ = try JSONSerialization.jsonObject(with: data)
    return try Canonical.decode(type, from: data)
  }
  private static func output(_ value: some Encodable) throws {
    let data = try Canonical.encode(value)
    guard data.count <= 2 * 1_024 * 1_024 else { throw ColophonError.malformed("Question response exceeds 2 MiB") }
    FileHandle.standardOutput.write(data + Data("\n".utf8))
  }
}
