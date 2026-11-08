import Foundation

// Computed decisions are emitted for report consumers. Decoders synthesize only the stored
// inputs, so a claimed `verified`/`passed`/`equal` flag can never override a recomputed result.
private struct ReportField: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init(_ value: String) { stringValue = value }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

extension CleanCopyReport {
    /// Encode all report inputs and the independently computed certification decision.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: ReportField.self)
        try container.encode(sourceLibraryID, forKey: ReportField("sourceLibraryID"))
        try container.encodeIfPresent(newLibraryID, forKey: ReportField("newLibraryID"))
        try container.encode(countsPerNamespace, forKey: ReportField("countsPerNamespace"))
        try container.encode(countsPerAuthor, forKey: ReportField("countsPerAuthor"))
        try container.encode(viewDigests, forKey: ReportField("viewDigests"))
        try container.encode(accounting, forKey: ReportField("accounting"))
        try container.encode(copiedBlobPaths, forKey: ReportField("copiedBlobPaths"))
        try container.encode(unresolved, forKey: ReportField("unresolved"))
        try container.encode(sourceUnchanged, forKey: ReportField("sourceUnchanged"))
        try container.encode(remainingOperations, forKey: ReportField("remainingOperations"))
        try container.encodeIfPresent(failure, forKey: ReportField("failure"))
        try container.encode(nextSteps, forKey: ReportField("nextSteps"))
        try container.encode(verified, forKey: ReportField("verified"))
    }
}

extension ViewDigests {
    /// Both complete normalized views are available and byte-equal.
    public var equal: Bool { reference != nil && reference == destination && reason == nil }
    /// Include the equality check alongside its two independently computed SHA-256 digests.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: ReportField.self)
        try container.encodeIfPresent(reference, forKey: ReportField("reference"))
        try container.encodeIfPresent(destination, forKey: ReportField("destination"))
        try container.encode(normalizedFields, forKey: ReportField("normalizedFields"))
        try container.encodeIfPresent(reason, forKey: ReportField("reason"))
        try container.encode(equal, forKey: ReportField("equal"))
    }
}

extension NamespaceAccounting {
    /// Include the checked namespace decision as well as every count and operation disposition.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: ReportField.self)
        try container.encode(expected, forKey: ReportField("expected"))
        try container.encode(imported, forKey: ReportField("imported"))
        try container.encode(unresolved, forKey: ReportField("unresolved"))
        try container.encode(authors, forKey: ReportField("authors"))
        try container.encode(operations, forKey: ReportField("operations"))
        try container.encode(failures, forKey: ReportField("failures"))
        try container.encode(passed, forKey: ReportField("passed"))
    }
}

extension AuthorAccounting {
    /// Include the independently checked author totals and decision.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: ReportField.self)
        try container.encode(expected, forKey: ReportField("expected"))
        try container.encode(imported, forKey: ReportField("imported"))
        try container.encode(unresolved, forKey: ReportField("unresolved"))
        try container.encode(passed, forKey: ReportField("passed"))
    }
}
