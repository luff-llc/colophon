import Foundation

/// The typed error of every 0.5 engine call (docs/bindings-05.md §3), as a Swift `Error` enum.
///
/// `code` is the protocol or binding code (`refused:fork`, `badSignature:origin`, `locked`, ...) and
/// `detail` is for logs: the bindings promise it never carries key material, and nothing here adds
/// any. Branch on the case (or `code`), never on the text.
public enum ColophonError: Error, Equatable, Hashable, Sendable {
    case malformed(code: String, detail: String)
    case badSignature(code: String, check: SignatureCheck?, detail: String)
    case newerFormat(code: String, detail: String)
    case unavailable(code: String, detail: String)
    /// A §19 refusal; `reason` is the spelling without the prefix (`fork`, `replay`, `vaultLocked`, ...).
    case refused(code: String, reason: String, detail: String)
    /// Access refused (`notGranted`, `revoked`, `expired`, `budgetSpent`, `notReadable`, `unavailable`).
    case denied(code: String, reason: AccountDenialReason, reasonRaw: String?, detail: String)
    /// A host callback failed (the record source, a translator); `detail` is the host's own message.
    case host(code: String, detail: String)
    /// A callback called back into the engine that was calling it (or a waiter gave up after 30 s).
    case reentered(code: String, detail: String)
    /// A one-shot object was used up, or a pairing step was in the wrong stage.
    case consumed(code: String, detail: String)
    case wrongObject(code: String, detail: String)
    case bound(code: String, detail: String)
    /// The engine found its source or home inconsistent and is unusable: discard it, open a new one.
    case integrity(code: String, detail: String)
    /// `lock` was called: open a new engine.
    case locked(code: String, detail: String)
    case internalFailure(code: String, detail: String)

    public init(_ error: AccountError) {
        switch error {
        case .Malformed(let c, let d): self = .malformed(code: c, detail: d)
        case .BadSignature(let c, let k, let d): self = .badSignature(code: c, check: k, detail: d)
        case .NewerFormat(let c, let d): self = .newerFormat(code: c, detail: d)
        case .Unavailable(let c, let d): self = .unavailable(code: c, detail: d)
        case .Refused(let c, let r, let d): self = .refused(code: c, reason: r, detail: d)
        case .Denied(let c, let r, let raw, let d): self = .denied(code: c, reason: r, reasonRaw: raw, detail: d)
        case .Host(let c, let d): self = .host(code: c, detail: d)
        case .Reentered(let c, let d): self = .reentered(code: c, detail: d)
        case .Consumed(let c, let d): self = .consumed(code: c, detail: d)
        case .WrongObject(let c, let d): self = .wrongObject(code: c, detail: d)
        case .Bound(let c, let d): self = .bound(code: c, detail: d)
        case .Integrity(let c, let d): self = .integrity(code: c, detail: d)
        case .Locked(let c, let d): self = .locked(code: c, detail: d)
        case .Internal(let c, let d): self = .internalFailure(code: c, detail: d)
        }
    }

    /// Converts a generated `AccountError` and leaves every other error as it is.
    public static func wrap(_ error: any Error) -> any Error {
        if let account = error as? AccountError { return ColophonError(account) }
        return error
    }

    public var code: String {
        switch self {
        case .malformed(let c, _), .newerFormat(let c, _), .unavailable(let c, _), .host(let c, _), .reentered(let c, _),
             .consumed(let c, _), .wrongObject(let c, _), .bound(let c, _), .integrity(let c, _), .locked(let c, _),
             .internalFailure(let c, _), .badSignature(let c, _, _), .refused(let c, _, _), .denied(let c, _, _, _): c
        }
    }
    public var detail: String {
        switch self {
        case .malformed(_, let d), .newerFormat(_, let d), .unavailable(_, let d), .host(_, let d), .reentered(_, let d),
             .consumed(_, let d), .wrongObject(_, let d), .bound(_, let d), .integrity(_, let d), .locked(_, let d),
             .internalFailure(_, let d), .badSignature(_, _, let d), .refused(_, _, let d), .denied(_, _, _, let d): d
        }
    }
    /// The §19 reason of a `refused` or `denied` error.
    public var reason: String? {
        switch self {
        case .refused(_, let r, _): r
        case .denied(_, let r, let raw, _): raw ?? String(describing: r)
        default: nil
        }
    }
    /// True when the account's own newer rules are the cause: the app must be updated, nothing is lost.
    public var isNewerFormat: Bool { if case .newerFormat = self { true } else { false } }
}

extension ColophonError: LocalizedError {
    public var errorDescription: String? { code + ": " + detail }
}

/// Fixed-text descriptions for the three records that carry a host secret, so that printing one, a
/// debugger summary or a `dump` never shows it. (The generated records are plain values; this hides
/// them from description and reflection, it does not erase the bytes.)
extension PrfAnswer: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "PrfAnswer(redacted)" }
    public var debugDescription: String { "PrfAnswer(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: []) }
}
extension UnlockSecret: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "UnlockSecret(redacted)" }
    public var debugDescription: String { "UnlockSecret(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: []) }
}
extension EpochAnswer: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "EpochAnswer(redacted)" }
    public var debugDescription: String { "EpochAnswer(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: []) }
}
