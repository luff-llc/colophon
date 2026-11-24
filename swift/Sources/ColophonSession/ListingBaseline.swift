import ColophonKit
import ColophonKitStorage

/// The complete listing an engine last took, with the paths that engine reported missing then. A later reconcile
/// compares the medium's fresh listing with it and hands the engine only the paths that were added or changed.
struct ListingBaseline {
    /// The engine that took the listing. Weak: a discarded engine is not kept alive by its baseline.
    weak var engine: ColophonEngine?
    /// The listing, strictly in path order.
    let entries: [MediumEntry]
    /// Paths the engine held that this listing did not name (`missing_covered`). One that reappears is judged by a
    /// full refresh, which is what clears it.
    let missing: Set<String>

    init(engine: ColophonEngine, entries: [MediumEntry], missing: Set<String>) {
        self.engine = engine; self.entries = entries; self.missing = missing
    }

    /// The baseline after `engine` took `entries` in full, or nil when the listing cannot serve as one (out of path
    /// order), so the next reconcile refreshes in full again.
    init?(engine: ColophonEngine, entries: [MediumEntry]) async throws {
        guard Self.isOrdered(entries) else { return nil }
        let missing = try await engine.run { try $0.missingCovered() }
        self.init(engine: engine, entries: entries, missing: Set(missing))
    }

    static func isOrdered(_ entries: [MediumEntry]) -> Bool {
        zip(entries, entries.dropFirst()).allSatisfy { $0.path < $1.path }
    }

    /// The entries of `new` that `old` (strictly in path order) does not hold with the same version, or nil when a full
    /// refresh must judge the listing: a path of `old` is absent from `new`, an entry has no version (the engine reads
    /// a path without one again on every refresh), or `new` is not strictly in path order.
    static func delta(from old: [MediumEntry], to new: [MediumEntry]) -> [MediumEntry]? {
        var changed: [MediumEntry] = []
        var index = old.startIndex
        var previous: String?
        for entry in new {
            guard let version = entry.version, !version.isEmpty else { return nil }
            if let previous, !(previous < entry.path) { return nil }
            previous = entry.path
            if index < old.endIndex, old[index].path < entry.path { return nil } // removed
            if index < old.endIndex, old[index].path == entry.path {
                if old[index].version != entry.version { changed.append(entry) }
                index += 1
            } else {
                changed.append(entry)
            }
        }
        return index == old.endIndex ? changed : nil
    }
}
