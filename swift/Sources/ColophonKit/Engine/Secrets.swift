import Foundation
import Security

/// What Swift can and cannot do about secret bytes.
///
/// Can: a secret made with `Data.secret(_:)` lives in memory this file allocated, and that memory is
/// overwritten (`memset_s`) when the last `Data` that refers to it is released, however the value was
/// passed around. `wipe()` overwrites a `Data` in place when its storage is not shared.
///
/// Cannot: Swift gives no control over copies it makes on its own (a `Data` that was copied before it
/// was handed over, a value in a register or on the stack, an array literal, a string), over pages the
/// operating system swaps out, or over the generated UniFFI lowering, which copies a record's `Data`
/// into a transfer buffer; the Rust side overwrites that copy (the zero-on-free allocator, §4 of
/// docs/bindings-05.md), the Swift value stays until it is released. Key providers return `Data`
/// that they allocated: the SDK wraps and releases it at once, and cannot reach their own copies.
extension Data {
    /// Copies `bytes` into memory that is overwritten when the returned `Data` is released.
    public static func secret<S: Sequence>(_ bytes: S) -> Data where S.Element == UInt8 {
        let source = Array(bytes)
        guard !source.isEmpty else { return Data() }
        let memory = UnsafeMutableRawPointer.allocate(byteCount: source.count, alignment: 16)
        source.withUnsafeBytes { memory.copyMemory(from: $0.baseAddress!, byteCount: source.count) }
        return Data(bytesNoCopy: memory, count: source.count, deallocator: .custom { pointer, count in
            _ = memset_s(pointer, count, 0, count)
            pointer.deallocate()
        })
    }

    /// Overwrites the bytes with zeros. If the storage is shared with another `Data`, Swift copies it
    /// first and only this value's own copy is cleared: use `Data.secret` for values that matter.
    public mutating func wipe() {
        guard !isEmpty else { return }
        withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress { _ = memset_s(base, buffer.count, 0, buffer.count) }
        }
        removeAll(keepingCapacity: false)
    }
}

/// Fresh random bytes for entropy and nonce seeds (the engine wants 32, 64 or 96 exactly).
public func colophonEntropy(_ count: Int) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    defer { bytes.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
    guard status == errSecSuccess else { throw KeyError.randomGenerationFailed(status) }
    return Data.secret(bytes)
}
