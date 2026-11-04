import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

public struct CaptureThoughtVerifyInput: Codable, Sendable {
  public let requestID: String
  public let noteID: String
  public let requestRevision: String
  public let expectedSource: SharedTranscriptReference?
  public let expectedQuote: String?

  public init(requestID: String, noteID: String, requestRevision: String,
    expectedSource: SharedTranscriptReference? = nil, expectedQuote: String? = nil)
  {
    self.requestID = requestID
    self.noteID = noteID
    self.requestRevision = requestRevision
    self.expectedSource = expectedSource
    self.expectedQuote = expectedQuote
  }

  private enum CodingKeys: String, CodingKey {
    case requestID, noteID, requestRevision, expectedSource, expectedQuote
  }

  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    guard values.contains(.expectedSource), values.contains(.expectedQuote) else {
      throw DecodingError.keyNotFound(values.contains(.expectedSource) ? CodingKeys.expectedQuote : CodingKeys.expectedSource,
        .init(codingPath: values.codingPath, debugDescription: "Expected source and quote keys must be explicit"))
    }
    requestID = try values.decode(String.self, forKey: .requestID)
    noteID = try values.decode(String.self, forKey: .noteID)
    requestRevision = try values.decode(String.self, forKey: .requestRevision)
    expectedSource = try values.decodeIfPresent(SharedTranscriptReference.self, forKey: .expectedSource)
    expectedQuote = try values.decodeIfPresent(String.self, forKey: .expectedQuote)
  }

  public func encode(to encoder: Encoder) throws {
    var values = encoder.container(keyedBy: CodingKeys.self)
    try values.encode(requestID, forKey: .requestID)
    try values.encode(noteID, forKey: .noteID)
    try values.encode(requestRevision, forKey: .requestRevision)
    if let expectedSource { try values.encode(expectedSource, forKey: .expectedSource) }
    else { try values.encodeNil(forKey: .expectedSource) }
    if let expectedQuote { try values.encode(expectedQuote, forKey: .expectedQuote) }
    else { try values.encodeNil(forKey: .expectedQuote) }
  }
}

/// A bounded read-only handoff for a selected enrolled agent. No recording bytes are exported.
public struct CaptureThoughtVerifiedBundle: Encodable, Sendable {
  public struct Signer: Encodable, Sendable {
    public let id: String
    public let label: String
    public let role: String
  }

  public struct Source: Encodable, Sendable {
    public let reference: SharedTranscriptReference
    public let startUTF16: Int
    public let lengthUTF16: Int
    public let quote: String
  }

  public struct Voice: Encodable, Sendable {
    public let blob: BlobRef
    public let mimeType: String
  }

  public let libraryID: String
  public let namespace: String
  public let requestID: String
  public let noteID: String
  public let requestRevision: String
  public let appSigner: Signer
  public let episode: String
  public let show: String
  public let seconds: Double
  public let source: Source?
  public let surroundingText: String
  public let originalText: String?
  public let voice: Voice?
  public let targetAgentID: String
  public let status: String
  public let sourceReady: Bool
  /// Digest of the complete payload sealed inside the admitted signed note.add operation.
  public let signedPayloadDigest: String
  /// Digest of the stable capture identity body, used by capture replay detection.
  public let captureDigest: String
  public let verifiedBy: String
  public let provisional: Bool
  public let humanConfirmationVerified: Bool
  public let authorshipLimit: String

  private enum CodingKeys: String, CodingKey {
    case libraryID, namespace, requestID, noteID, requestRevision, appSigner, episode, show,
      seconds, source, surroundingText, originalText, voice, targetAgentID, status,
      sourceReady, signedPayloadDigest, captureDigest, verifiedBy, provisional,
      humanConfirmationVerified, authorshipLimit
  }

  public func encode(to encoder: Encoder) throws {
    var values = encoder.container(keyedBy: CodingKeys.self)
    try values.encode(libraryID, forKey: .libraryID)
    try values.encode(namespace, forKey: .namespace)
    try values.encode(requestID, forKey: .requestID)
    try values.encode(noteID, forKey: .noteID)
    try values.encode(requestRevision, forKey: .requestRevision)
    try values.encode(appSigner, forKey: .appSigner)
    try values.encode(episode, forKey: .episode)
    try values.encode(show, forKey: .show)
    try values.encode(seconds, forKey: .seconds)
    if let source { try values.encode(source, forKey: .source) }
    else { try values.encodeNil(forKey: .source) }
    try values.encode(surroundingText, forKey: .surroundingText)
    if let originalText { try values.encode(originalText, forKey: .originalText) }
    else { try values.encodeNil(forKey: .originalText) }
    if let voice { try values.encode(voice, forKey: .voice) }
    else { try values.encodeNil(forKey: .voice) }
    try values.encode(targetAgentID, forKey: .targetAgentID)
    try values.encode(status, forKey: .status)
    try values.encode(sourceReady, forKey: .sourceReady)
    try values.encode(signedPayloadDigest, forKey: .signedPayloadDigest)
    try values.encode(captureDigest, forKey: .captureDigest)
    try values.encode(verifiedBy, forKey: .verifiedBy)
    try values.encode(provisional, forKey: .provisional)
    try values.encode(humanConfirmationVerified, forKey: .humanConfirmationVerified)
    try values.encode(authorshipLimit, forKey: .authorshipLimit)
  }
}

public enum CaptureThoughtVerifyError: Error, Equatable {
  case invalidRequest, missingSignedRequest, wrongSigner, wrongTarget, wrongSource
  case sourceUnavailable, requestInactive, noCurrentAccess
}

public struct CaptureThoughtVerifier {
  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  public func verify(_ input: CaptureThoughtVerifyInput) throws -> CaptureThoughtVerifiedBundle {
    guard !input.requestID.isEmpty, !input.noteID.isEmpty, !input.requestRevision.isEmpty else {
      throw CaptureThoughtVerifyError.invalidRequest
    }
    let authority = try replica.authority()
    guard let verifier = authority.members[replica.identity.id], verifier.role == .agent,
      verifier.revokedAt == nil, let grant = verifier.current,
      grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true
    else { throw CaptureThoughtVerifyError.noCurrentAccess }
    let matching = try replica.read(Podcasts.namespace).admitted.filter {
      $0.operation.id == input.requestRevision && $0.operation.kind == Podcasts.ContentKind.addNote
    }
    guard matching.count == 1, let signed = matching.first else {
      throw CaptureThoughtVerifyError.missingSignedRequest
    }
    let state: CaptureThoughtState
    do {
      state = try CaptureThoughtService(replica: replica).state(noteID: input.noteID,
        requestRevision: input.requestRevision)
    } catch { throw CaptureThoughtVerifyError.missingSignedRequest }
    let request = state.request
    guard request.requestID == input.requestID, request.noteID == input.noteID,
      request.revision == input.requestRevision, request.authorID == signed.author
    else { throw CaptureThoughtVerifyError.missingSignedRequest }
    let projectedNote = try replica.state(of: Podcasts.self).notes[input.noteID]
    guard projectedNote?.creationRevision == input.requestRevision,
      projectedNote?.authorID == signed.author else { throw CaptureThoughtVerifyError.missingSignedRequest }
    guard let app = authority.members[signed.author], app.role == .app || app.role == .device else {
      throw CaptureThoughtVerifyError.wrongSigner
    }
    guard request.targetAgentID == replica.identity.id else { throw CaptureThoughtVerifyError.wrongTarget }
    guard state.status != .held, state.status != .cancelled, state.status != .conflict else {
      throw CaptureThoughtVerifyError.requestInactive
    }
    guard state.sourceReady else { throw CaptureThoughtVerifyError.sourceUnavailable }
    let anchor = request.snapshot.anchor
    guard (anchor == nil) == (input.expectedSource == nil && input.expectedQuote == nil),
      (anchor != nil) == (input.expectedSource != nil && input.expectedQuote != nil)
    else { throw CaptureThoughtVerifyError.wrongSource }
    if let expected = input.expectedSource, anchor?.reference != expected {
      throw CaptureThoughtVerifyError.wrongSource
    }
    if let expected = input.expectedQuote, anchor?.quote != expected {
      throw CaptureThoughtVerifyError.wrongSource
    }
    let capture = signed.operation.payload["captureThought"]?.object
    guard let captureDigest = capture?["digest"]?.string else {
      throw CaptureThoughtVerifyError.invalidRequest
    }
    let source = anchor.map { CaptureThoughtVerifiedBundle.Source(reference: $0.reference,
      startUTF16: $0.startUTF16, lengthUTF16: $0.lengthUTF16, quote: $0.quote) }
    let voice: CaptureThoughtVerifiedBundle.Voice?
    if let blob = request.voice, let mime = request.voiceMimeType {
      voice = .init(blob: blob, mimeType: mime)
    } else { voice = nil }
    let status: String = switch state.status {
    case .queued: "queued"
    case .awaitingAgent: "awaitingAgent"
    case .responded: "responded"
    case .cancelled: "cancelled"
    case .conflict: "conflict"
    case .held: "held"
    }
    return CaptureThoughtVerifiedBundle(libraryID: authority.libraryID, namespace: Podcasts.namespace,
      requestID: request.requestID, noteID: request.noteID, requestRevision: request.revision,
      appSigner: .init(id: signed.author, label: signed.authorLabel, role: app.role.rawValue),
      episode: request.snapshot.episode, show: request.snapshot.show, seconds: request.snapshot.seconds,
      source: source, surroundingText: request.snapshot.surroundingText,
      originalText: request.text, voice: voice, targetAgentID: replica.identity.id,
      status: status, sourceReady: state.sourceReady,
      signedPayloadDigest: Canonical.digest(try Canonical.encode(signed.operation.payload)),
      captureDigest: captureDigest, verifiedBy: replica.identity.id, provisional: true,
      humanConfirmationVerified: false,
      authorshipLimit: "Signature proves an enrolled app or device authored note.add; it does not prove a person physically tapped Save.")
  }
}
