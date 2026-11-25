import Foundation
import Testing
@testable import ColophonHosts
import ColophonSession

/// What the shipping surface replays itself, and what it must never carry: the `offset.json` cases through
/// `sessionClockSample` (§S7), and that the shipped package neither links nor exports the conformance crate.
@Suite struct ShippingSurfaceTests {
    static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    /// `offset.json`'s single samples; its integers are read exactly (offsets saturate to the signed 64-bit range).
    struct Offsets: Decodable {
        struct Case: Decodable { let now: UInt64; let t: UInt64; let echo: UInt64; let hold: UInt64; let rtt: UInt64; let offset: Int64; let error: UInt64 }
        let cases: [Case]
    }

    @Test func theOffsetCasesReplayThroughTheShippingClockSample() throws {
        let data = try Data(contentsOf: Self.root.appendingPathComponent("conformance/0.6-sessions/offset.json"))
        let file = try JSONDecoder().decode(Offsets.self, from: data)
        #expect(file.cases.count == 9)
        for k in file.cases {
            let s = sessionClockSample(now: k.now, t: k.t, echo: k.echo, hold: k.hold)
            #expect([s.rtt, UInt64(bitPattern: s.offset), s.error] == [k.rtt, UInt64(bitPattern: k.offset), k.error], "\(k)")
        }
    }

    @Test func theShippedPackageNeitherLinksNorExportsTheConformanceCrate() throws {
        let manifest = try String(contentsOf: Self.root.appendingPathComponent("Package.swift"), encoding: .utf8)
        #expect(!manifest.localizedCaseInsensitiveContains("conformance"))
        let sources = Self.root.appendingPathComponent("swift/Sources")
        let files = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)?.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" } ?? []
        #expect(!files.isEmpty)
        for file in files where file.lastPathComponent != "ColophonBindings.swift" {
            let text = try String(contentsOf: file, encoding: .utf8)
            #expect(!text.contains("ColophonConformance") && !text.contains("colophon_conformance"), "\(file.lastPathComponent)")
        }
        let bindings = try String(contentsOf: sources.appendingPathComponent("ColophonKit/Generated/ColophonBindings.swift"), encoding: .utf8)
        #expect(!bindings.contains("Conformance"), "no conformance name in the shipping bindings")
    }
}
