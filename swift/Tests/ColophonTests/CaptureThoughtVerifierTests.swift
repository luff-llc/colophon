import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

private let captureFixtureExportPath = ProcessInfo.processInfo.environment["COLOPHON_CAPTURE_FIXTURE_DIR"]
private let captureFixtureExportEnabled = captureFixtureExportPath != nil

@Suite struct CaptureThoughtVerifierTests {
  private struct Fixture {
    let store = MemoryStore()
    let phone = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let other = SoftwareIdentity()

    init() throws {
      let root = SoftwareIdentity()
      let (holder, _) = try AuthorityHolder.create(in: store, label: "Synthetic capture verifier", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Taupe", role: .app,
        custody: .software, namespaces: [Podcasts.namespace])
      try holder.admit(agent.publicIdentity, label: "Workbench fixture", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
      try holder.admit(other.publicIdentity, label: "Other fixture agent", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
    }

    var phoneReplica: Replica { Replica(store: store, identity: phone) }
    var verifier: CaptureThoughtVerifier {
      CaptureThoughtVerifier(replica: Replica(store: store, identity: agent))
    }
  }

  @Test func syntheticPinnedCaptureExportsOnlyExactBoundedSignedBundle() throws {
    let f = try Fixture()
    let transcript = "Before the exact line. After."
    _ = try f.phoneReplica.saveTranscript(TranscriptDocument(text: transcript, words: nil),
      episode: "episode", show: "show", source: "publisher", language: "en")
    let possibleReference = try SharedTranscriptService(replica: f.phoneReplica).reference(episode: "episode")
    let reference = try #require(possibleReference)
    let quote = "the exact line"
    let range = try #require(transcript.range(of: quote))
    let utf16 = NSRange(range, in: transcript)
    let anchor = TranscriptNoteAnchor(reference: reference, startUTF16: utf16.location,
      lengthUTF16: utf16.length, quote: quote)
    let snapshot = CaptureThoughtSnapshot(episode: "episode", show: "show", seconds: 9.5,
      anchor: anchor, surroundingText: transcript)
    let request = try CaptureThoughtService(replica: f.phoneReplica).save(snapshot: snapshot,
      input: .text("What changed?"), targetAgentID: f.agent.id, requestID: "synthetic-request")
    let input = CaptureThoughtVerifyInput(requestID: request.requestID, noteID: request.noteID,
      requestRevision: request.revision, expectedSource: reference, expectedQuote: quote)
    let output = try f.verifier.verify(input)
    #expect(output.requestRevision == request.revision)
    #expect(output.appSigner.id == f.phone.id)
    #expect(output.appSigner.label == "Taupe")
    #expect(output.appSigner.role == "app")
    #expect(output.verifiedBy == f.agent.id)
    #expect(output.source?.reference == reference)
    #expect(output.source?.startUTF16 == utf16.location)
    #expect(output.source?.quote == quote)
    #expect(output.originalText == "What changed?")
    #expect(output.surroundingText == transcript)
    #expect(output.status == "awaitingAgent")
    #expect(output.sourceReady)
    #expect(!output.signedPayloadDigest.isEmpty)
    #expect(!output.captureDigest.isEmpty)
    #expect(output.provisional)
    #expect(!output.humanConfirmationVerified)
    #expect(output.authorshipLimit.contains("does not prove"))
    let encoded = try Canonical.encode(output)
    let json = try Canonical.decode(JSONValue.self, from: encoded)
    #expect(json.object?["voice"] == .null)
    #expect(throws: CaptureThoughtVerifyError.wrongSource) {
      try f.verifier.verify(.init(requestID: request.requestID, noteID: request.noteID,
        requestRevision: request.revision, expectedSource: reference, expectedQuote: "changed quote"))
    }
    #expect(throws: CaptureThoughtVerifyError.missingSignedRequest) {
      try f.verifier.verify(.init(requestID: request.requestID, noteID: request.noteID,
        requestRevision: "wrong-revision", expectedSource: reference, expectedQuote: quote))
    }
    #expect(throws: CaptureThoughtVerifyError.wrongTarget) {
      try CaptureThoughtVerifier(replica: Replica(store: f.store, identity: f.other)).verify(input)
    }
  }

  @Test func syntheticVoiceDescriptorOmitsOriginalBytesAndMissingKeysReject() throws {
    let f = try Fixture()
    let bytes = Data("private original recording".utf8)
    let request = try CaptureThoughtService(replica: f.phoneReplica).save(
      snapshot: .init(episode: "episode", show: "show", seconds: 3),
      input: .voice(data: bytes, mimeType: "audio/x-caf", text: "Also typed"),
      targetAgentID: f.agent.id, requestID: "synthetic-voice")
    let output = try f.verifier.verify(.init(requestID: request.requestID, noteID: request.noteID,
      requestRevision: request.revision))
    #expect(output.voice?.blob == request.voice)
    #expect(output.voice?.mimeType == "audio/x-caf")
    #expect(output.originalText == "Also typed")
    let json = String(decoding: try Canonical.encode(output), as: UTF8.self)
    #expect(!json.contains("private original recording"))
    let incomplete = Data("{\"requestID\":\"x\",\"noteID\":\"y\",\"requestRevision\":\"z\"}".utf8)
    #expect(throws: DecodingError.self) {
      try Canonical.decode(CaptureThoughtVerifyInput.self, from: incomplete)
    }
  }

  /// Opt in with COLOPHON_CAPTURE_FIXTURE_DIR to make a disposable on-disk fixture for a real
  /// `colophon context capture-verify` run. Only a fresh synthetic agent key is exported.
  @Test(.enabled(if: captureFixtureExportEnabled))
  func exportSyntheticDiskFixtureForCLI() throws {
    let basePath = try #require(captureFixtureExportPath)
    let folder = URL(filePath: basePath, directoryHint: .isDirectory)
      .appending(path: "capture-\(UUID().uuidString.lowercased())", directoryHint: .isDirectory)
    let library = folder.appending(path: "library", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: library, withIntermediateDirectories: true)
    let store = FolderStore(library)
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let (holder, _) = try AuthorityHolder.create(in: store, label: "Synthetic Workbench capture", root: root,
      firstMember: phone.publicIdentity, memberLabel: "Synthetic Taupe", role: .app,
      custody: .software, namespaces: [Podcasts.namespace])
    try holder.admit(agent.publicIdentity, label: "Synthetic Workbench", role: .agent,
      custody: .software, namespaces: [Podcasts.namespace], write: true)
    let phoneReplica = Replica(store: store, identity: phone)
    let text = "A synthetic exact line for the verifier."
    _ = try phoneReplica.saveTranscript(TranscriptDocument(text: text, words: nil),
      episode: "synthetic-episode", show: "synthetic-show", source: "publisher", language: "en")
    let possibleReference = try SharedTranscriptService(replica: phoneReplica).reference(episode: "synthetic-episode")
    let reference = try #require(possibleReference)
    let quote = "exact line"
    let range = try #require(text.range(of: quote))
    let utf16 = NSRange(range, in: text)
    let anchor = TranscriptNoteAnchor(reference: reference, startUTF16: utf16.location,
      lengthUTF16: utf16.length, quote: quote)
    let request = try CaptureThoughtService(replica: phoneReplica).save(
      snapshot: .init(episode: "synthetic-episode", show: "synthetic-show", seconds: 17,
        anchor: anchor, surroundingText: text), input: .text("Why this line?"),
      targetAgentID: agent.id, requestID: "synthetic-capture")
    let input = CaptureThoughtVerifyInput(requestID: request.requestID, noteID: request.noteID,
      requestRevision: request.revision, expectedSource: reference, expectedQuote: quote)
    let verified = try CaptureThoughtVerifier(replica: Replica(store: store, identity: agent)).verify(input)
    let keyFile = folder.appending(path: "agent.json")
    try Canonical.encode(agent).write(to: keyFile, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
    try Canonical.encode(input).write(to: folder.appending(path: "request.json"), options: .atomic)
    try Canonical.encode(verified).write(to: folder.appending(path: "verified.json"), options: .atomic)
    let instructions = "colophon \"\(library.path)\" context capture-verify --identity \"\(keyFile.path)\" < \"\(folder.appending(path: "request.json").path)\"\n"
    try Data(instructions.utf8).write(to: folder.appending(path: "invoke.txt"), options: .atomic)
    print("Synthetic capture CLI fixture: \(folder.path)")
  }
}
