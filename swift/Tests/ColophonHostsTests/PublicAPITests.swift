import Foundation
import Testing

/// The public surface of `ColophonHosts`, pinned. Nothing public may hand out the engine, a raw signer, an endpoint, a
/// stream client or an account view, or let a caller act on them outside a host's serial queue: those stay internal
/// (`HostAccount`, `SessionCellHost.current`), and the session reaches the hosts only through `@_spi(Hosts)`.
///
/// Every `public` (or `open`) declaration in `swift/Sources/ColophonHosts` is compared with `ColophonHosts.public-api`
/// beside this file. A change to the public surface changes that file in the same commit, where review sees it; run the
/// suite with `COLOPHON_UPDATE_PUBLIC_API=1` to rewrite it.
@Suite struct PublicAPITests {
    static let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    static let sources = here.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources")
    static let pinned = here.appendingPathComponent("ColophonHosts.public-api")
    /// Names no public declaration may mention.
    static let forbidden = [#"\bAccountEngine\b"#, #"\bSessionEndpoint\b"#, #"\bHomeStream\b"#, #"\bSessionAccountView\b"#, #"(?<!Colophon)\bHostAccount\b"#,
                            #"\bSessionHostAccount\b"#, #"\bSessionHostAccess\b"#, #"\bsignRaw\b"#, #"\bengine\("#, #"\bstreamCall\b"#, #"\bcurrent\b"#]

    /// Each public declaration of `text`, from its `public` to its body or the end of its signature, on one line.
    static func declarations(_ text: String) -> [String] {
        var out: [String] = []
        let lines = text.components(separatedBy: "\n").map { line -> String in
            // Comments are not declarations.
            if let r = line.range(of: "//") { return String(line[..<r.lowerBound]) }
            return line
        }
        var k = 0
        while k < lines.count {
            let line = lines[k]
            guard line.range(of: #"^\s*(@\S+\s+)*(nonisolated\s+)?(public|open)\s"#, options: .regularExpression) != nil else { k += 1; continue }
            var decl = line.trimmingCharacters(in: .whitespaces)
            var depth = decl.filter { $0 == "(" }.count - decl.filter { $0 == ")" }.count
            while depth > 0, !decl.contains("{"), k + 1 < lines.count {
                k += 1
                let next = lines[k].trimmingCharacters(in: .whitespaces)
                decl += " " + next
                depth += next.filter { $0 == "(" }.count - next.filter { $0 == ")" }.count
            }
            if let brace = decl.firstIndex(of: "{") { decl = String(decl[..<brace]) }
            out.append(decl.trimmingCharacters(in: .whitespaces))
            k += 1
        }
        return out
    }
    static func surface() throws -> [String] {
        let folder = sources.appendingPathComponent("ColophonHosts")
        let files = try FileManager.default.contentsOfDirectory(atPath: folder.path).filter { $0.hasSuffix(".swift") }.sorted()
        return try files.flatMap { file in
            try declarations(String(contentsOf: folder.appendingPathComponent(file), encoding: .utf8)).map { "\(file): \($0)" }
        }
    }

    @Test func thePublicSurfaceIsExactlyThePinnedOne() throws {
        let now = try Self.surface()
        if ProcessInfo.processInfo.environment["COLOPHON_UPDATE_PUBLIC_API"] == "1" {
            try (now.joined(separator: "\n") + "\n").write(to: Self.pinned, atomically: true, encoding: .utf8)
        }
        let pinned = try String(contentsOf: Self.pinned, encoding: .utf8).components(separatedBy: "\n").filter { !$0.isEmpty }
        let added = now.filter { !pinned.contains($0) }, removed = pinned.filter { !now.contains($0) }
        #expect(added.isEmpty && removed.isEmpty, "public surface changed; added: \(added); removed: \(removed)")
    }

    @Test func noPublicDeclarationHandsOutTheEngineASignerAnEndpointOrAClient() throws {
        for entry in try Self.surface() {
            // The declaration alone, without the file it is in.
            let decl = entry.split(separator: ":", maxSplits: 1).last.map(String.init) ?? entry
            for pattern in Self.forbidden {
                #expect(decl.range(of: pattern, options: .regularExpression) == nil, "\(decl) matches \(pattern)")
            }
        }
    }

    @Test func theSessionReachesTheHostsOnlyThroughSPI() throws {
        let folder = Self.sources.appendingPathComponent("ColophonSession")
        for file in try FileManager.default.contentsOfDirectory(atPath: folder.path) where file.hasSuffix(".swift") {
            let text = try String(contentsOf: folder.appendingPathComponent(file), encoding: .utf8)
            for line in text.components(separatedBy: "\n") where line.contains("public") && (line.contains("SessionHostAccess") || line.contains("hostAccess")) {
                #expect(line.contains("@_spi(Hosts)"), "\(file): \(line.trimmingCharacters(in: .whitespaces))")
            }
            // Nothing else in the session exposes the engine's handle.
            for line in text.components(separatedBy: "\n") where line.contains("public") && line.contains("-> AccountEngine") {
                #expect(line.contains("@_spi(Hosts)") || file == "SessionHostAccess.swift", "\(file): \(line.trimmingCharacters(in: .whitespaces))")
            }
        }
    }
}
