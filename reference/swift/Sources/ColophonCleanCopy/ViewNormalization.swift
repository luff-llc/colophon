import Foundation

/// Fixed JSON paths removed from complete domain projections. Wildcards match one path
/// component only, never arbitrary descendants. User payloads and extension bags are untouched.
enum ViewNormalization {
    private static let stamp = ["revision", "author", "authorLabel", "origin", "clock"]
    static let fields: [String: [String]] = {
        func paths(_ bases: [String], _ names: [String]) -> [String] {
            bases.flatMap { base in names.map { base + "/" + $0 } }
        }
        let books = paths(["/books/*/book", "/books/*/loan", "/notes/*/note", "/conflicts/*/*"], stamp)
            + paths(["/books/*/heads"], ["metadata", "plan", "progress", "loan", "activity"])
            + paths(["/books/*/readings/*"], ["id", "revision"])
            + paths(["/conflicts/*/*"], ["operation", "expected", "found"])
            + ["/conflicts/*/*/candidate/expect", "/invalid/*/operation", "/notes/*/alternatives/*"]
        let saved = paths(["/items/*", "/sources/*", "/sourceMetadata/*", "/images/*", "/checkpoints/*",
                           "/feeds/*/value", "/answers/*", "/subscriptions/*", "/receipts/*",
                           "/conflicts/*/candidate", "/conflicts/*/attribution"], stamp)
            + paths(["/items/*"], ["added"])
            + paths(["/checkpoints/*"], ["updated"])
            + paths(["/conflicts/*"], ["operation", "expected", "found"])
            + ["/conflicts/*/candidate/expect", "/conflicts/*/candidate/expectActivity", "/invalid/*", "/diagnostics/*/operation"]
        let listeningRows = ["/shows/*", "/episodes/*", "/queue", "/notes/*", "/playlists/*", "/transcripts/*",
                             "/jobs/*", "/contributions/*", "/preferences/*", "/recordings/*", "/receipts/*", "/conflicts/*",
                             "/conflicts/*/candidate"]
        let listening = paths(listeningRows, stamp)
            + paths(["/episodes/*"], ["positionRevision", "stateRevision", "updated", "stateUpdated"])
            + paths(["/notes/*", "/jobs/*"], ["created", "updated"])
            + paths(["/episodes/*/positionAttribution", "/episodes/*/stateAttribution", "/notes/*/acceptance",
                     "/jobs/*/responseAttribution"], stamp)
            + paths(["/conflicts/*"], ["expected", "found"])
            + ["/conflicts/*/candidate/expect", "/invalid/*"]
        let noteRows = ["/notebooks/*", "/notes/*", "/cells/*", "/entries/*", "/attachments/*", "/runs/*", "/proposals/*",
                        "/conflicts/*", "/conflicts/*/candidate"]
        let notes = paths(noteRows, stamp + ["created", "updated", "touched"])
            + ["/notebooks/*/orderRevision", "/proposals/*/reviewRevision", "/proposals/*/inputs/*",
               "/runs/*/sourceRevision", "/conflicts/*/expected", "/conflicts/*/found", "/conflicts/*/payload/expect", "/invalid/*"]
        return ["reading.books": books.sorted(), "reading.saved": saved.sorted(),
                "listening.podcasts": listening.sorted(), "notes": notes.sorted()]
    }()

    // These tables are indexed by destination operation IDs. Remove only such keys, retaining
    // every value (including user content and outcome) in canonical order; stable keys stay keys.
    private static let operationKeyedMaps: [String: Set<String>] = [
        "reading.saved": ["/receipts"], "listening.podcasts": ["/receipts"],
    ]
    static func printedFields(namespace: String) -> [String] {
        (fields[namespace] ?? []) + (operationKeyedMaps[namespace] ?? []).sorted().map {
            $0 + "/@key (destination operation identity only; all values retained)"
        }
    }

    static func canonical(_ bytes: Data, namespace: String, operationIDs: Set<String>) throws -> Data {
        guard let patterns = fields[namespace] else { throw CleanCopyError.workspaceMismatch }
        let patternsParts = patterns.map { $0.split(separator: "/").map(String.init) }
        func matches(_ path: [String]) -> Bool {
            patternsParts.contains { pattern in
                pattern.count == path.count && zip(pattern, path).allSatisfy { $0 == "*" || $0 == $1 }
            }
        }
        func walk(_ value: Any, _ path: [String]) throws -> Any {
            if let object = value as? [String: Any] {
                var result: [String: Any] = [:]
                for key in object.keys.sorted() {
                    let childPath = path + [key]
                    if matches(childPath) {
                        // Revision-valued maps retain their domain object keys and multiplicity.
                        if namespace == "notes", path.count == 3, path[0] == "proposals", path[2] == "inputs" {
                            result[key] = NSNull()
                        }
                        continue
                    }
                    if let child = object[key] { result[key] = try walk(child, childPath) }
                }
                if operationKeyedMaps[namespace]?.contains("/" + path.joined(separator: "/")) == true {
                    var identityValues: [Data] = []
                    for key in result.keys.sorted() where operationIDs.contains(key) {
                        if let value = result.removeValue(forKey: key) { identityValues.append(try canonicalJSON(value)) }
                    }
                    // An envelope preserves stable keys and the multiplicity of identity-keyed rows.
                    return ["stableKeys": result, "operationKeyedValues": try identityValues.sorted { $0.lexicographicallyPrecedes($1) }.map {
                        try JSONSerialization.jsonObject(with: $0, options: .fragmentsAllowed)
                    }]
                }
                return result
            }
            if let array = value as? [Any] {
                // Removing an identity-only array value keeps its position and multiplicity.
                return try array.enumerated().map { index, child -> Any in
                    let childPath = path + [String(index)]
                    return matches(childPath) ? NSNull() : try walk(child, childPath)
                }
            }
            return value
        }
        return try canonicalJSON(walk(JSONSerialization.jsonObject(with: bytes), []))
    }
}

/// UTF-8 JSON with byte-sorted keys at every depth and unescaped slashes. Array order, user
/// strings, nulls and numeric values are preserved. No locale-sensitive key sorting is used.
func canonicalJSON(_ value: Any) throws -> Data {
    if let object = value as? [String: Any] {
        var result = Data("{".utf8)
        for (index, key) in object.keys.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }).enumerated() {
            if index > 0 { result.append(0x2c) }
            result += try JSONSerialization.data(withJSONObject: key, options: [.fragmentsAllowed, .withoutEscapingSlashes])
            result.append(0x3a)
            if let child = object[key] { result += try canonicalJSON(child) }
        }
        result.append(0x7d); return result
    }
    if let array = value as? [Any] {
        var result = Data("[".utf8)
        for (index, child) in array.enumerated() {
            if index > 0 { result.append(0x2c) }
            result += try canonicalJSON(child)
        }
        result.append(0x5d); return result
    }
    return try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes])
}
