import Foundation
import Testing
import ColophonListeningKit

/// `conformance/0.6-sessions/now-playing-anchor.json` through the listening kit: every canonical encoding, every decode
/// verdict (valid, and the first failing check for each invalid input), and every translation, exactly.
@Suite struct NowPlayingAnchorTests {
    static let file = ShippingSurfaceTests.root.appendingPathComponent("conformance/0.6-sessions/now-playing-anchor.json")

    struct Vectors: Decodable {
        struct A: Decodable {
            let at: Int64, episode: String, playing: Bool, positionMs: Int64, ratePermille: Int64, show: String
            func value() throws -> NowPlayingAnchor {
                try NowPlayingAnchor(episode: episode, show: show, positionMs: positionMs, ratePermille: ratePermille, playing: playing, at: at)
            }
        }
        struct P: Decodable { let label: String; let playing: Bool }
        struct Encode: Decodable { let name: String; let anchor: A; let text: String }
        struct Presence: Decodable { let name: String; let presence: P; let text: String }
        struct Decode: Decodable {
            let name: String, kind: String, text: String?, base64: String?, valid: Bool, error: String?, anchor: A?, presence: P?
            var bytes: Data { base64.flatMap { Data(base64Encoded: $0) } ?? Data((text ?? "").utf8) }
        }
        /// A signed 64-bit input: a JSON number, or a decimal string beyond ±(2^53 − 1).
        struct Wide: Decodable {
            let value: Int64
            init(from decoder: any Decoder) throws {
                let c = try decoder.singleValueContainer()
                if let n = try? c.decode(Int64.self) { value = n; return }
                guard let v = Int64(try c.decode(String.self)) else {
                    throw DecodingError.dataCorruptedError(in: c, debugDescription: "not a signed 64-bit integer")
                }
                value = v
            }
        }
        struct Translate: Decodable {
            struct Expect: Decodable { let ageMs: Int64, capped: Bool, elapsedMs: Int64, errorBoundMs: Int64, positionMs: Int64 }
            let name: String, anchor: A, nowMs: Wide, offsetMs: Wide, offsetErrorMs: Wide, sampleAgeMs: Wide, maximumProjectionMs: Wide
            let expect: Expect
        }
        struct Rules: Decodable { let errorOrder: [String]; let maximumBytes: Int }
        let format: String
        let rules: Rules
        let encode: [Encode]
        let presence: [Presence]
        let decode: [Decode]
        let translate: [Translate]
    }
    static func vectors() throws -> Vectors { try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: file)) }

    @Test func theFileIsTheOneThisKitImplements() throws {
        let v = try Self.vectors()
        #expect(v.format == "colophon/now-playing-anchor-vectors/6")
        let order = NowPlayingCodingError.allCases.map(\.rawValue)
        #expect(v.rules.errorOrder == order)
        #expect(v.rules.maximumBytes == NowPlayingAnchor.maximumBytes)
        #expect(v.encode.count == 8 && v.presence.count == 2 && v.decode.count == 65 && v.translate.count == 36)
    }

    @Test func everyAnchorEncodesToItsCanonicalText() throws {
        for c in try Self.vectors().encode {
            let anchor = try c.anchor.value()
            #expect(String(decoding: anchor.encoded, as: UTF8.self) == c.text, "\(c.name)")
            #expect(try NowPlayingAnchor(decoding: Data(c.text.utf8)) == anchor, "\(c.name)")
        }
        for c in try Self.vectors().presence {
            let p = try NowPlayingPresence(label: c.presence.label, playing: c.presence.playing)
            #expect(String(decoding: p.encoded, as: UTF8.self) == c.text, "\(c.name)")
        }
    }

    @Test func everyInputGetsItsVerdict() throws {
        for c in try Self.vectors().decode {
            if c.kind == "anchor" {
                let result = Result { () throws(NowPlayingCodingError) in try NowPlayingAnchor(decoding: c.bytes) }
                switch result {
                case .success(let anchor):
                    #expect(c.valid, "\(c.name)")
                    let want = try c.anchor?.value()
                    #expect(anchor == want, "\(c.name)")
                case .failure(let error):
                    #expect(error.rawValue == (c.error ?? "valid"), "\(c.name)")
                }
            } else {
                let result = Result { () throws(NowPlayingCodingError) in try NowPlayingPresence(decoding: c.bytes) }
                switch result {
                case .success(let p):
                    #expect(c.valid, "\(c.name)")
                    #expect(p.label == c.presence?.label && p.playing == c.presence?.playing, "\(c.name)")
                case .failure(let error):
                    #expect(error.rawValue == (c.error ?? "valid"), "\(c.name)")
                }
            }
        }
    }

    @Test func everyTranslationIsExact() throws {
        for c in try Self.vectors().translate {
            let clock = NowPlayingClockOffset(offsetMs: c.offsetMs.value, errorMs: c.offsetErrorMs.value, sampleAgeMs: c.sampleAgeMs.value)
            let p = try c.anchor.value().projected(nowMs: c.nowMs.value, clock: clock, maximumProjectionMs: c.maximumProjectionMs.value)
            let got: [Int64] = [p.ageMs, p.elapsedMs, p.positionMs, p.errorBoundMs, p.capped ? 1 : 0]
            let want: [Int64] = [c.expect.ageMs, c.expect.elapsedMs, c.expect.positionMs, c.expect.errorBoundMs, c.expect.capped ? 1 : 0]
            #expect(got == want, "\(c.name)")
        }
    }

    @Test func restampingKeepsTheTrajectoryAndPausingStopsIt() throws {
        let a = try NowPlayingAnchor(episode: "e", show: "s", positionMs: 10_000, ratePermille: 1_500, playing: true, at: 1_000)
        let offset = NowPlayingClockOffset(offsetMs: 500, errorMs: 2, sampleAgeMs: 0)
        let r = a.restamped(nowMs: 3_000, clock: offset, maximumProjectionMs: 75_000)
        // On the publisher's clock 3,500 − 1,000 = 2,500 ms passed: 10,000 + 3,750.
        #expect(r.positionMs == 13_750 && r.at == 3_000 && r.playing && r.ratePermille == 1_500)
        #expect(r.projected(nowMs: 5_000, maximumProjectionMs: 75_000).positionMs == a.projected(nowMs: 5_000, clock: offset, maximumProjectionMs: 75_000).positionMs)
        let p = a.paused(nowMs: 2_000, maximumProjectionMs: 75_000)
        #expect(p.positionMs == 11_500 && !p.playing && p.at == 2_000)
        #expect(p.projected(nowMs: 99_000, maximumProjectionMs: 75_000).positionMs == 11_500)
        #expect(NowPlayingAnchor.defaultMaximumProjectionMs() == 75_000)
    }

    @Test func valuesOutsideTheFormatAreRefusedWhenMade() {
        #expect(throws: NowPlayingCodingError.outOfRange) { try NowPlayingAnchor(episode: "e", show: "s", positionMs: -1, ratePermille: 1_000, playing: true, at: 0) }
        #expect(throws: NowPlayingCodingError.badText) { try NowPlayingAnchor(episode: " ", show: "s", positionMs: 0, ratePermille: 1_000, playing: true, at: 0) }
        #expect(throws: NowPlayingCodingError.badText) { try NowPlayingPresence(label: "", playing: false) }
    }
}
