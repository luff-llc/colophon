import Foundation

public enum SourceRow: Codable, Equatable, Sendable {
    case version(SourceVersion), image(ImageRow), metadata(SourceMetadata)
    public init(from decoder: any Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let image = try? c.decode(ImageRow.self) { self = .image(image) }
        else if let version = try? c.decode(SourceVersion.self) { self = .version(version) }
        else { self = .metadata(try c.decode(SourceMetadata.self)) }
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self { case .version(let v): try c.encode(v); case .image(let v): try c.encode(v); case .metadata(let v): try c.encode(v) }
    }
}
