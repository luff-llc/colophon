import Foundation
import Testing
import ColophonSavedKit

func sourceManifest(original: [String: Any]? = blob(), metadata: [String: Any] = blob("b", media: "application/json"), origin: [String: Any] = ["kind":"file"]) throws -> [String: Any] {
    let id = sha(try jsonData(["colophon/reading.saved/source/1", original?["digest"] ?? NSNull(), metadata["digest"] ?? NSNull()]))
    var value: [String: Any] = ["id":id, "metadata":metadata, "mediaType":"text/plain", "origin":origin, "capturedAt":"2026-11-06T00:00:00Z", "extractionVersion":1, "coverage":"complete"]
    value["original"] = original
    return value
}

@MainActor struct SavedCommandTests {
    @Test func everySavedCommandAndNonemptyEvidenceQueries() async throws {
        let h = DomainHarness(); try await h.start(); let ns = "reading.saved"
        let capture = try await h.send(ns, "capture", ["id":"item", "title":"Document", "consumption":NSNull(), "retention":"saved"])
        try await h.send(ns, "setState", ["id":"item", "consumption":"inProgress", "expect":capture])
        try await h.send(ns, "editMetadata", ["id":"item", "creator":"Writer", "summary":"Summary", "collection":"", "tags":["tag"], "expect":capture])
        let manifest = try sourceManifest()
        let source = try #require(manifest["id"] as? String)
        let retained = try await h.send(ns, "retainSource", ["id":source, "item":"item", "manifest":manifest, "select":true, "expect":NSNull()])
        let selected = try await h.send(ns, "selectSource", ["item":"item", "source":source, "expect":retained])
        try await h.send(ns, "position", ["item":"item", "source":source, "position":["kind":"passage", "id":"p", "offsetUTF16":2], "expect":NSNull()])
        let anchor: [String: Any] = ["kind":"text", "passageID":"p", "startUTF16":0, "lengthUTF16":4, "quote":"text"]
        try await h.send(ns, "reviseAnnotation", ["id":"a", "thread":"thread", "item":"item", "source":source, "parents":[], "action":"create", "anchor":anchor, "text":"A thought"])
        try await h.send(ns, "tagAnnotations", ["id":"tags", "threads":["thread"], "tag":"kept", "included":true])
        let feed = try await h.send(ns, "followFeed", ["id":"feed", "url":"https://example.org/feed", "title":"Feed", "folders":[]])
        let organized = try await h.send(ns, "organizeFeed", ["id":"feed", "folders":[["Daily"]], "expect":feed])
        let refreshed = try await h.send(ns, "refreshFeed", ["id":"feed", "response":blob("c"), "entries":[["id":"entry", "title":"Article", "publisherIdentity":"guid", "author":"Author", "summary":"Summary"]], "expect":organized])
        try await h.send(ns, "unfollowFeed", ["id":"feed", "expect":refreshed])
        try await h.send(ns, "reviseView", ["id":"view-root", "view":"view", "parents":[], "name":"Saved", "query":["retention":"saved"], "deleted":false])
        try await h.send(ns, "changeReview", ["id":"review", "action":"enable"])
        let evidence: [String: Any] = ["source":source, "annotation":"a", "anchor":anchor]
        try await h.send(ns, "keepAnswer", ["id":"answer", "question":"Why?", "claims":[["text":"Because", "citations":[evidence]]], "evidence":[evidence], "engine":"test", "runtime":"test", "promptRevision":"1"])
        try await h.send(ns, "setAnswerVisibility", ["id":"visibility", "answer":"answer", "parents":[], "hidden":false])
        try await h.send(ns, "reviseConnection", ["id":"connection-root", "connection":"connection", "parents":[], "source":["item":"item", "source":source, "annotation":"a"], "target":["item":"item", "source":source], "relation":"related", "reason":"Context", "retracted":false])
        try await h.send(ns, "setMagazineSubscription", ["id":"subscription", "publication":"wired", "status":"active", "plan":"digital", "expect":NSNull()])
        let imageURL = "https://example.org/image.png"
        let candidateID = sha(try jsonData(["colophon/reading.saved/image/1", "item", source, 0, imageURL]))
        let candidate: [String: Any] = ["id":candidateID, "itemID":"item", "source":source, "index":0, "sourceURL":imageURL, "alt":"Image"]
        let asset: [String: Any] = ["candidate":candidate, "blob":blob("d", media:"image/png"), "mime":"image/png", "width":100, "height":100, "observedURLs":[imageURL], "capturedAt":"2026-11-06T00:00:00Z"]
        try await h.send(ns, "retainImages", ["item":"item", "source":source, "assets":[asset], "coverage":["results":[["candidate":candidateID, "outcome":"retained"]]], "expect":selected])
        let item = try await h.value(ns, "item", ["id":"item"])
        let heads = try #require(item["heads"] as? [String: Any])
        let checkpoint = try await h.send(ns, "captureReading", ["id":"checkpoint", "item":"item", "source":try sourceManifest(original:nil, metadata:blob("c",media:"application/json"), origin:["kind":"browserExtraction"]), "position":["kind":"passage", "id":"p", "offsetUTF16":4], "notes":[["id":"seed", "anchor":anchor, "text":"Captured"]], "expect":try #require(heads["activity"])])
        try await h.send(ns, "selectReadingCheckpoint", ["item":"item", "checkpoint":"checkpoint", "expect":checkpoint])
        try await h.send(ns, "capture", ["id":"imported", "title":"Imported"])
        let raw = blob("e", media:"application/json")
        let provenance: [String: Any] = ["version":1, "documentID":"doc", "sourceRecordDigest":String(repeating:"a",count:64), "rawExport":raw, "importedAt":"2026-11-06T00:00:00Z"]
        let metadataValue: [String: Any] = ["version":1, "provenance":provenance, "values":["title":"Imported", "author":"Writer", "summary":"", "sourceName":"Reader", "tags":[]]]
        let metadata = try await h.send(ns, "retainSourceMetadata", ["id":"metadata", "item":"imported", "kind":"readerMetadata", "value":metadataValue, "raw":raw])
        let store = SavedStore(session: h.session)
        let metadataPage = try await store.load(SourcesQuery(item:"imported", kind:.versions)).get()
        #expect(metadataPage.total == 1)
        let importedManifest = try sourceManifest(original:blob("f"), origin:["kind":"reader", "documentID":"doc", "sourceRecordDigest":String(repeating:"a",count:64), "rawDigest":try #require(raw["digest"])])
        try await h.send(ns, "attachOriginal", ["item":"imported", "metadata":"metadata", "manifest":importedManifest, "expect":metadata, "expectActivity":metadata])
        let answer = try await store.load(AnswerQuery(id:"answer")).get()
        #expect(answer.claims.first?.text == "Because")
        let connections = try await store.load(ConnectionsQuery()).get()
        #expect(connections.rows.first?.reasonPreview?.text == "Context")
        let images = try await store.load(SourcesQuery(item:"item", kind:.images)).get()
        #expect(images.total == 1)
        let entries = try await store.load(FeedEntriesQuery(feed:"feed")).get()
        #expect(entries.rows.first?.title == "Article")
        let review = try await store.load(ReviewQueueQuery()).get()
        #expect(review.enabled)
        #expect(review.eligibleCount == 2)
        let detail = try await store.load(ItemQuery(id:"item")).get()
        try await h.send(ns, "delete", ["id":"item", "expectActivity":try #require(detail.heads.activity)])
        let deleted = try await store.load(ItemQuery(id:"item"))
        #expect(deleted == .failure(.deleted))
        try await h.noInvalid(ns)
        #expect(h.exercised.count == 24)
    }
}
