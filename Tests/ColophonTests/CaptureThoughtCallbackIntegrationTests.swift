import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

private let callbackEnvironment = ProcessInfo.processInfo.environment
private let callbackFixturePath = callbackEnvironment["COLOPHON_CAPTURE_CALLBACK_FIXTURE_DIR"]
private let callbackEnvelopePath = callbackEnvironment["COLOPHON_CAPTURE_CALLBACK_ENVELOPE"]
private let callbackOutputPath = callbackEnvironment["COLOPHON_CAPTURE_CALLBACK_OUTPUT_DIR"]
private let callbackEnabled = callbackFixturePath != nil && callbackEnvelopePath != nil && callbackOutputPath != nil

/// Opt-in only. This reuses an existing synthetic agent key and copies the fixture library before
/// a signed write; no provider is executed and no member or grant is created.
@Suite struct CaptureThoughtCallbackIntegrationTests {
  private enum Rejection: Error, Equatable {
    case malformedEnvelope, wrongEnvelopeDigest, wrongPin, wrongRecipient, wrongProvider
  }

  @Test(.enabled(if: callbackEnabled))
  func preparedSyntheticCallbackIsSignedAndAttachedWithoutChangingOriginalNote() throws {
    let fixture = URL(filePath: try #require(callbackFixturePath), directoryHint: .isDirectory)
    let envelopeURL = URL(filePath: try #require(callbackEnvelopePath))
    let outputBase = URL(filePath: try #require(callbackOutputPath), directoryHint: .isDirectory)
    let envelopeData = try Data(contentsOf: envelopeURL)
    let envelope = try Canonical.decode(JSONValue.self, from: envelopeData)
    let prepared = try Canonical.decode(JSONValue.self,
      from: Data(contentsOf: fixture.appending(path: "verified.json")))
    let providerEvidence = try Canonical.decode(JSONValue.self,
      from: Data(contentsOf: envelopeURL.deletingLastPathComponent()
        .appending(path: "capture-roundtrip-provider.json")))
    let existingKey = try Canonical.decode(SoftwareIdentity.self,
      from: Data(contentsOf: fixture.appending(path: "agent.json")))

    // The fixture's original library remains immutable evidence. Only the copy below receives
    // the signed callback; do not copy or export the agent key into the result directory.
    let output = outputBase.appending(path: "capture-callback-\(UUID().uuidString.lowercased())",
      directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    let signedLibrary = output.appending(path: "library", directoryHint: .isDirectory)
    try FileManager.default.copyItem(at: fixture.appending(path: "library", directoryHint: .isDirectory),
      to: signedLibrary)
    let replica = Replica(store: FolderStore(signedLibrary), identity: existingKey)
    let verifierInput = try Canonical.decode(CaptureThoughtVerifyInput.self,
      from: Data(contentsOf: fixture.appending(path: "request.json")))
    let verified = try CaptureThoughtVerifier(replica: replica).verify(verifierInput)
    let verifiedJSON = try Canonical.decode(JSONValue.self, from: Canonical.encode(verified))
    guard verifiedJSON == prepared else { throw Rejection.wrongPin }
    try Self.validate(envelope, verified: verifiedJSON, signerID: existingKey.id,
      providerEvidence: providerEvidence)

    // A changed recipient pin must fail locally, without enrolling or impersonating anyone.
    var wrongRecipient = try #require(envelope.object)
    var transport = try #require(wrongRecipient["transport"]?.object)
    transport["signerId"] = .string("not-the-selected-fixture-agent")
    wrongRecipient["transport"] = .object(transport)
    wrongRecipient["envelopeDigest"] = .string(try Self.digestExcludingEnvelopeDigest(wrongRecipient))
    #expect(throws: Rejection.wrongRecipient) {
      try Self.validate(.object(wrongRecipient), verified: verifiedJSON, signerID: existingKey.id,
        providerEvidence: providerEvidence)
    }

    let command = try #require(envelope.object?["nativeCommand"]?.object)
    let requestID = try Self.string(command, "requestID")
    let requestRevision = try Self.string(command, "requestRevision")
    let text = try Self.string(command, "text")
    let commandID = try Self.string(command, "commandID")
    let service = CaptureThoughtService(replica: replica)
    let before = try service.state(noteID: verifierInput.noteID, requestRevision: verifierInput.requestRevision)
    let noteBefore = try #require(replica.state(of: Podcasts.self).notes[verifierInput.noteID])
    let source = try #require(before.request.snapshot.anchor?.reference)
    let documentBefore = try SharedTranscriptService(replica: replica).resolve(source)
    let operationCountBefore = try replica.read(Podcasts.namespace).admitted.count
    #expect(throws: CaptureThoughtError.staleRequest) {
      try service.respond(requestID: requestID, requestRevision: "stale-fixture-revision",
        text: text, commandID: commandID)
    }
    #expect(try replica.read(Podcasts.namespace).admitted.count == operationCountBefore)

    let signedResponse = try service.respond(requestID: requestID, requestRevision: requestRevision,
      text: text, commandID: commandID)
    let replay = try service.respond(requestID: requestID, requestRevision: requestRevision,
      text: text, commandID: commandID)
    #expect(replay == signedResponse)
    #expect(throws: CaptureThoughtError.commandIDConflict) {
      try service.respond(requestID: requestID, requestRevision: requestRevision,
        text: "Changed replay", commandID: commandID)
    }
    #expect(try replica.read(Podcasts.namespace).admitted.count == operationCountBefore + 1)
    let after = try service.state(noteID: verifierInput.noteID, requestRevision: verifierInput.requestRevision)
    let noteAfter = try #require(replica.state(of: Podcasts.self).notes[verifierInput.noteID])
    let documentAfter = try SharedTranscriptService(replica: replica).resolve(source)
    #expect(after.status == .responded)
    #expect(after.response == signedResponse)
    #expect(signedResponse.agentID == existingKey.id)
    #expect(signedResponse.text == text)
    #expect(noteAfter == noteBefore)
    #expect(documentAfter == documentBefore)

    let provider = try #require(envelope.object?["provider"]?.object)
    let result: JSONValue = .object([
      "schema": .string("workbench.synthetic-capture-callback-result.v1"),
      "fixtureOnly": .bool(true), "library": .string(signedLibrary.path),
      "libraryID": .string(verified.libraryID), "namespace": .string(Podcasts.namespace),
      "requestID": .string(requestID), "noteID": .string(verifierInput.noteID),
      "requestRevision": .string(requestRevision),
      "responseRevision": .string(signedResponse.revision),
      "responseSignerID": .string(signedResponse.agentID),
      "responseSignerLabel": .string(signedResponse.agentLabel),
      "responseText": .string(signedResponse.text),
      "originalNoteUnchanged": .bool(noteAfter == noteBefore),
      "sourceUnchanged": .bool(documentAfter == documentBefore),
      "exactReplayEqual": .bool(replay == signedResponse),
      "changedReplayRejected": .bool(true), "staleRevisionRejected": .bool(true),
      "wrongRecipientRejectedBeforeAdmission": .bool(true),
      "provider": .object([
        "name": provider["name"] ?? .null, "runId": provider["runId"] ?? .null,
        "handoffId": provider["handoffId"] ?? .null,
        "responseDigest": provider["responseDigest"] ?? .null,
        "textDigest": provider["textDigest"] ?? .null
      ]),
      "providerIdentityIsTransportSigner": .bool(false),
      "humanConfirmationVerified": .bool(false), "provisional": .bool(true)
    ])
    try Canonical.encode(result).write(to: output.appending(path: "callback-result.json"), options: .atomic)
    print("Synthetic signed callback library: \(signedLibrary.path)")
  }

  private static func validate(_ envelope: JSONValue, verified: JSONValue, signerID: String,
    providerEvidence: JSONValue) throws
  {
    guard let root = envelope.object, root["schema"]?.string == "workbench.synthetic-capture-callback.v1",
      root["fixtureOnly"]?.bool == true, root["humanConfirmationVerified"]?.bool == false,
      root["provisional"]?.bool == true,
      let claimedDigest = root["envelopeDigest"]?.string,
      claimedDigest == (try digestExcludingEnvelopeDigest(root)),
      let request = root["request"]?.object, let bundle = verified.object,
      let command = root["nativeCommand"]?.object, let provider = root["provider"]?.object,
      let transport = root["transport"]?.object
    else { throw Rejection.wrongEnvelopeDigest }
    for key in ["libraryID", "namespace", "requestID", "noteID", "requestRevision",
      "captureDigest", "signedPayloadDigest", "source"] where request[key] != bundle[key]
    { throw Rejection.wrongPin }
    guard command["requestID"] == request["requestID"],
      command["requestRevision"] == request["requestRevision"],
      let commandID = command["commandID"]?.string,
      commandID == "fixture-claude-capture-callback-v1",
      let text = command["text"]?.string, !text.isEmpty,
      text.utf16.count <= CaptureThoughtService.maximumTextUTF16,
      provider["textDigest"]?.string == Canonical.digest(try Canonical.encode(JSONValue.string(text))),
      providerEvidence.object?["result"]?.object?["summary"]?.string == text,
      providerEvidence.object?["responseDigest"] == provider["responseDigest"],
      providerEvidence.object?["runId"] == provider["runId"],
      providerEvidence.object?["handoffId"] == provider["handoffId"],
      providerEvidence.object?["metadata"]?.object?["sessionId"] == provider["sessionId"],
      providerEvidence.object?["metadata"]?.object?["models"] == provider["models"]
    else { throw Rejection.wrongProvider }
    guard transport["signerId"]?.string == signerID,
      transport["signerId"] == bundle["targetAgentID"],
      transport["signerId"] == bundle["verifiedBy"],
      transport["status"]?.string == "prepared-not-submitted",
      bundle["status"]?.string == "awaitingAgent", bundle["sourceReady"]?.bool == true
    else { throw Rejection.wrongRecipient }
  }

  private static func digestExcludingEnvelopeDigest(_ envelope: [String: JSONValue]) throws -> String {
    var body = envelope
    body["envelopeDigest"] = nil
    return Canonical.digest(try Canonical.encode(JSONValue.object(body)))
  }

  private static func string(_ object: [String: JSONValue], _ key: String) throws -> String {
    guard let value = object[key]?.string else { throw Rejection.malformedEnvelope }
    return value
  }
}
