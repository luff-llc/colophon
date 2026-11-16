import Compression
import Foundation
import Testing
@testable import ColophonTest
import ColophonSession

/// Unit tests of the app's own rules (hosted in the app, no home needed).
@MainActor @Suite(.serialized) struct ColophonTestTests {
    /// A home that answers by echoing what it was sent (a record, a call envelope) in a refusal.
    struct EchoingHome: HomeTransport {
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            let echo = "{\"result\":\"refused:SECRET-\(String(decoding: request.body, as: UTF8.self))\",\"body\":\"\(String(decoding: request.body, as: UTF8.self))\"}"
            return HttpAnswer(status: 400, headers: [], body: Data(echo.utf8))
        }
    }
    struct PlainRefusal: HomeTransport {
        let body: String
        func send(_ request: HttpRequest) async throws -> HttpAnswer { HttpAnswer(status: 403, headers: [], body: Data(body.utf8)) }
    }
    private func request(_ body: String) -> HttpRequest {
        HttpRequest(ticket: 1, home: "h", method: .put, url: "https://home.test/v1/libraries/t1/records/ops/a.json", headers: [], body: Data(body.utf8))
    }

    @Test func aRefusalShowsOnlyAResultTheSpecAllows() async throws {
        let observer = HomeObserver()
        let echo = MappedTransport(homePrefix: "https://home.test/v1/libraries/", reachPrefix: "", observer: observer, inner: EchoingHome())
        _ = try await echo.send(request("sealed-record-bytes"))
        let refusal = try #require(observer.snapshot().lastRefusal)
        #expect(refusal.status == 400)
        #expect(refusal.detail == "no result", "nothing from the body: \(refusal.detail)")
        #expect(!refusal.detail.contains("sealed-record-bytes"))

        let plain = MappedTransport(homePrefix: "https://home.test/v1/libraries/", reachPrefix: "", observer: observer,
                                    inner: PlainRefusal(body: "{\"result\":\"refused:revoked\",\"extra\":\"x\"}"))
        _ = try await plain.send(request("x"))
        #expect(observer.snapshot().lastRefusal?.detail == "refused:revoked")
    }

    @Test func theResultGrammar() {
        for good in ["ok", "malformed", "badSignature", "newerFormat", "unavailable", "refused:revoked", "refused:outOfScope"] {
            #expect(ResultCode.isValid(good), "\(good)")
        }
        for bad in ["", "refused:", "refused:Revoked", "refused:a b", "refused:<script>", "refused:" + String(repeating: "a", count: 49),
                    "error", "OK", "refused:revoked\n"] {
            #expect(!ResultCode.isValid(bad), "\(bad)")
        }
        #expect(ResultCode.of(body: Data("not json".utf8)) == nil)
        #expect(ResultCode.of(body: Data("[\"refused:revoked\"]".utf8)) == nil)
    }

    @Test func aHeadKeepsOnlyAPlainDate() {
        #expect(HomeObserver.plainDate("2026-11-16T03:38:25.872Z") == "2026-11-16T03:38:25.872Z")
        #expect(HomeObserver.plainDate("2026-11-16T03:38:25Z<b>") == "-")
        #expect(HomeObserver.plainDate(42) == "-")
    }

    @Test func aDecompressionBombIsRefused() throws {
        // 40 MiB of zeros, raw DEFLATE: a few tens of KiB.
        let zeros = Data(count: 40 * 1024 * 1024)
        let bomb = try (zeros as NSData).compressed(using: .zlib) as Data
        #expect(bomb.count < 200_000)
        let text = PairingPayload.invitePrefix + PairingPayload.b64url(bomb)
        #expect(throws: PairingPayload.Failure.tooLarge) { try PairingPayload.decodeInvite(text) }
        // A small payload still round-trips.
        let request = try PairingPayload.encodeRequest(Data("{\"a\":1}".utf8))
        #expect(try PairingPayload.decodeRequest(request) == Data("{\"a\":1}".utf8))
    }

    /// A link only fills the confirmation screen: no settings, no files, no request.
    @Test func aJoinLinkStoresNothingUntilConfirmed() async throws {
        let model = AppModel()
        await model.resetDevice()
        let invite = try PairingPayload.encode(.init(homePrefix: "https://home.test/v1/libraries/", slot: "tlink", account: String(repeating: "a", count: 64),
                                                     history: ["authority/00000001.json": Data("{}".utf8)]))
        await model.open(URL(string: "colophontest://join?p=\(invite)")!)
        #expect(model.pendingInvite?.host == "home.test")
        #expect(model.pendingInvite?.accountShort == "aaaaaaaa…aaaa")
        #expect(model.settings.slot == nil, "nothing stored before confirmation")
        #expect(!FileManager.default.fileExists(atPath: Paths.records.path), "no history written before confirmation")
        #expect(model.session == nil)
        // Confirming an invite whose history does not verify stores nothing either.
        await model.confirmJoin()
        #expect(model.settings.slot == nil)
        #expect(!FileManager.default.fileExists(atPath: Paths.records.path))
        #expect(model.actionError != nil)
        model.cancelJoin()
        await model.resetDevice()
    }

    /// A request link never approves: a device without an account takes none, and nothing is scanned or stored for it.
    @Test func aRequestLinkNeverApproves() async throws {
        let model = AppModel()
        await model.resetDevice()
        await model.open(URL(string: "colophontest://request?p=CTR1.abc")!)
        #expect(model.scanned == nil, "a device without an account takes no request")
        #expect(model.actionError != nil)
    }
}
