import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Testing

@Suite struct TranscriptSelectionTests {
  @Test(arguments: ["publisher", "onDevice"])
  func lowerPrioritySubmissionRetainsTheSelectedBytesAcrossReplicas(source: String) async throws {
    let phoneStore = MemoryStore(), macStore = MemoryStore()
    let phone = SoftwareIdentity(), mac = SoftwareIdentity()
    let (holder, _) = try AuthorityHolder.create(in: phoneStore, label: "Transcript selection", root: SoftwareIdentity(),
      firstMember: phone.publicIdentity, memberLabel: "Phone", custody: .software, namespaces: [Podcasts.namespace])
    try holder.admit(mac.publicIdentity, label: "Mac", role: .device, custody: .software,
      namespaces: [Podcasts.namespace], write: true)
    let phoneReplica = Replica(store: phoneStore, identity: phone)
    let macReplica = Replica(store: macStore, identity: mac)
    let original = TranscriptDocument(text: "The harbour walk.",
      words: [.init(text: "The harbour walk.", start: 0, end: 3)])
    try phoneReplica.saveTranscript(original, episode: "episode", show: "show", source: source, language: "en")
    let before = try phoneReplica.state(of: Podcasts.self)
    let firstRecord = try #require(before.transcripts["episode"])

    // The source string is unchanged, but the newer untimed submission loses by the existing contract.
    let alternative = TranscriptDocument(text: "A different untimed text.", words: nil)
    let submitted = try phoneReplica.saveTranscript(alternative, episode: "episode", show: "show", source: source,
      language: "fr")
    let submittedBlob = try #require(BlobRef(json: submitted.payload["blob"]))
    let selected = try phoneReplica.state(of: Podcasts.self)
    let selectedRecord = try #require(selected.transcripts["episode"])
    let selectedDocument = try phoneReplica.transcript(of: "episode", in: selected)
    #expect(submittedBlob.digest != selectedRecord.blob.digest)
    #expect(selectedRecord == firstRecord)
    #expect(selectedDocument == original)

    let sync = StoreSync(local: macStore, remote: LocalRemote(phoneStore))
    try await sync.run()
    let received = try macReplica.state(of: Podcasts.self)
    let receivedDocument = try macReplica.transcript(of: "episode", in: received)
    #expect(received.transcripts["episode"] == firstRecord)
    #expect(receivedDocument == original)
    // Losing the selection does not discard the submitted source material.
    let retainedBytes = try macReplica.blob(submittedBlob, in: Podcasts.namespace)
    let retained = try #require(retainedBytes)
    let retainedAlternative = try Canonical.decode(TranscriptDocument.self, from: retained)
    #expect(retainedAlternative == alternative)

    // An equal-ranked correction on Mac becomes current on both replicas after the return sync.
    let correction = TranscriptDocument(text: "The corrected harbour walk.",
      words: [.init(text: "The corrected harbour walk.", start: 1, end: 4)])
    try macReplica.saveTranscript(correction, episode: "episode", show: "show", source: source, language: "en")
    try await sync.run()
    let returned = try phoneReplica.state(of: Podcasts.self)
    let returnedDocument = try phoneReplica.transcript(of: "episode", in: returned)
    #expect(returnedDocument == correction)
    #expect(returned.transcripts["episode"]?.blob.digest != firstRecord.blob.digest)
    // The older projection still resolves to its original immutable bytes.
    let oldDocument = try phoneReplica.transcript(of: "episode", in: before)
    #expect(oldDocument == original)
  }
}
