import Foundation
import Testing
import ColophonListeningKit

@MainActor struct ListeningCommandTests {
    @Test func everyPodcastCommandIncludingAuthenticatedWorkers() async throws {
        let h = DomainHarness(); try await h.start(); let ns = "listening.podcasts"
        let agent = try await h.agent()
        let worker = try #require(agent.memberID)
        let show = try await h.send(ns, "follow", ["id":"show", "url":"https://example.org/feed", "title":"Show"])
        try await h.send(ns, "editShow", ["id":"show", "title":"New title", "skipIntro":5, "skipOutro":2, "expect":show])
        try await h.send(ns, "setPreferences", ["id":"prefs", "changes":[["scope":"global", "field":"speed", "value":1.25, "expect":NSNull()]]])
        try await h.send(ns, "episode", ["id":"e", "show":"show", "title":"Episode", "duration":120])
        let state = try await h.send(ns, "setState", ["id":"e", "show":"show", "consumption":"inProgress"])
        let position = try await h.send(ns, "position", ["id":"e", "show":"show", "seconds":30, "duration":120])
        let recovery = try await h.send(ns, "recoverPosition", ["id":"e", "show":"show", "seconds":10, "duration":120, "expectedPosition":position, "expectedState":state, "inProgress":true])
        let queue = try await h.send(ns, "queue", ["episodes":["e"], "expect":NSNull()])
        try await h.send(ns, "completePlayback", ["id":"end", "baseQueue":["e"], "expect":queue, "events":[["eventID":"event", "episode":"e", "show":"show", "audio":"https://example.org/audio", "endSeconds":120, "actualDuration":120, "expectedPosition":recovery, "expectedState":recovery]]])
        let note = try await h.send(ns, "addNote", ["id":"n", "episode":"e", "show":"show", "text":"Original", "seconds":12])
        let stale = try await h.send(ns, "editNote", ["id":"n", "text":"Alternative", "expect":NSNull()])
        let resolved = try await h.send(ns, "resolveNote", ["id":"n", "text":"Reviewed", "expect":note, "resolves":[stale]])
        try await h.send(ns, "deleteNote", ["id":"n", "expect":resolved])
        let recording = String(repeating: "a", count: 64)
        try await h.send(ns, "setSegments", ["episode":"e", "show":"show", "recording":recording, "source":"person", "segments":[["start":1, "end":3, "kind":"sponsor"]]])
        let transcript = try await h.send(ns, "saveTranscript", ["id":"t", "episode":"e", "show":"show", "blob":blob(), "source":"publisher", "timed":true, "recording":recording])
        try await h.send(ns, "setChapters", ["episode":"e", "show":"show", "recording":recording, "source":"publisher", "entries":[["start":0, "title":"Opening"]]])
        try await h.send(ns, "savePlaylist", ["id":"p", "name":"Daily", "mode":"manual", "episodes":["e"]])
        let reference: [String: Any] = ["transcript":"t", "revision":transcript, "blob":blob(), "episode":"e"]
        let anchor: [String: Any] = ["reference":reference, "startUTF16":0, "lengthUTF16":5, "quote":"hello"]
        let claims: [[String: Any]] = [["text":"A claim", "citations":[anchor]]]
        try await h.send(ns, "saveAnswer", ["id":"answer", "question":"Why?", "claims":claims])
        let request = try await h.send(ns, "requestTranscript", ["id":"job", "episode":"e", "show":"show", "worker":worker, "audio":blob(), "recording":recording, "language":"en"])
        try await h.send(ns, "supplyTranscript", ["id":"job", "request":request, "result":blob("b")], using: agent)
        try await h.send(ns, "cancelTranscript", ["id":"job", "request":request])
        let question = try await h.send(ns, "askQuestion", ["id":"q", "question":"Why?", "scope":[anchor], "worker":worker, "expires":"2099-01-01T00:00:00Z"])
        let answer = try await h.send(ns, "answerQuestion", ["id":"q", "request":question, "scopeDigest":sha(jsonData([anchor])), "claims":claims], using: agent)
        try await h.send(ns, "acceptAnswer", ["id":"q", "request":question, "response":answer])
        try await h.send(ns, "cancelQuestion", ["id":"q", "request":question])
        let capture = try await h.send(ns, "addNote", ["id":"capture-note", "episode":"e", "show":"show", "text":"Original", "capture":["requestID":"capture", "originalText":"Original", "surroundingText":"Around", "targetAgentID":worker]])
        try await h.send(ns, "respondCapture", ["id":"capture", "request":capture, "text":"Response"], using: agent)
        try await h.send(ns, "cancelCapture", ["id":"capture", "request":capture])
        let proposal = try await h.send(ns, "proposeContext", ["id":"proposal", "contributionID":"context", "reference":reference, "text":"Context", "citation":"hello", "expect":NSNull()], using: agent)
        try await h.send(ns, "acceptContext", ["id":"acceptance", "contributionID":"context", "reference":reference, "proposal":proposal, "expect":proposal])
        let store = ListeningStore(session: h.session)
        let episode = try await store.load(EpisodeQuery(id: "e")).get()
        #expect(episode.row.consumption == "completed")
        let jobPage = try await store.load(JobsQuery(kind: .transcript)).get()
        #expect(jobPage.rows.first?.status == "cancelled")
        let answerResult = try await store.load(ContributionsQuery(id: "q", kind: .answer)).get()
        guard case .detail(let retained) = answerResult else { Issue.record("Expected admitted answer"); return }
        #expect(retained.claims?.first?.text == "A claim")
        let playback = try await store.load(PlaybackContextQuery(episode: "e", recording: recording)).get()
        #expect(playback.preferences["speed"] == .number(1.25))
        try await h.send(ns, "unfollow", ["id":"show"])
        try await h.noInvalid(ns)
        #expect(h.exercised.count == 30)
    }
}
