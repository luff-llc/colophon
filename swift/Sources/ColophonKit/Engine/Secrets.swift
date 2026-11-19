import Foundation
import Security

/// Secret bytes in memory this type owns exclusively: allocated here, written once, overwritten with
/// zeros (`memset_s`) when the last reference goes, never resized, never copied by Swift.
///
/// Every secret the SDK handles lives in one of these: PRF outputs, ECDH results, epoch shares, the
/// device-held sealed-state key, action entropy, software private scalars. A secret reaches an export
/// only through `withUnsafeData(_:)`, which lends a `Data` over this memory for the duration of the call
/// (no copy on the Swift side); the generated UniFFI lowering then copies it into a Rust transfer buffer,
/// which the Rust zero-on-free allocator overwrites when it is freed (docs/bindings-05.md §4).
///
/// What the SDK cannot reach, exactly (stated once here; each platform entry point names its own case):
/// * a copy a platform API makes before it hands the value over: the PRF output AuthenticationServices
///   keeps inside its credential object, CryptoKit's own `SharedSecret` and `SymmetricKey` storage (CryptoKit
///   zeroes those when they are released), the `CFData` a Keychain read returns and the Keychain's own
///   buffers on write;
/// * registers and stack slots the compiler uses while bytes are copied in, and pages the system swaps;
/// * the generated 0.4 `KeyProvider` callback interface, which can only return a `Data` (see `SoftwareKeys`).
public final class SecretBytes: @unchecked Sendable {
    // Immutable after `init`: the memory is written once, read through borrowed views, and zeroed in `deinit`.
    private let base: UnsafeMutableRawPointer?
    public let count: Int

    /// Allocates `count` zeroed bytes and lets `body` fill them. If `body` throws, the memory is zeroed and freed.
    public init(count: Int, initializingWith body: (UnsafeMutableRawBufferPointer) throws -> Void) rethrows {
        precondition(count >= 0, "a negative secret length")
        guard count > 0 else {
            self.count = 0; base = nil
            try body(UnsafeMutableRawBufferPointer(start: nil, count: 0))
            return
        }
        let memory = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 16)
        memory.initializeMemory(as: UInt8.self, repeating: 0, count: count)
        do { try body(UnsafeMutableRawBufferPointer(start: memory, count: count)) }
        catch {
            _ = memset_s(memory, count, 0, count)
            memory.deallocate()
            throw error
        }
        self.count = count; base = memory
    }

    /// Copies `bytes` in. Use it at the one moment a platform hands the SDK a secret, inside that API's own
    /// `withUnsafeBytes`, so that no intermediate `Data` or `Array` exists.
    public convenience init(copying bytes: UnsafeRawBufferPointer) {
        self.init(count: bytes.count) { target in
            if let source = bytes.baseAddress, let destination = target.baseAddress {
                destination.copyMemory(from: source, byteCount: bytes.count)
            }
        }
    }

    /// Copies any contiguous bytes in (a CryptoKit `SharedSecret` or `SymmetricKey`, a test's array).
    public convenience init<Bytes: ContiguousBytes>(copying bytes: Bytes) {
        let count = bytes.withUnsafeBytes { $0.count }
        self.init(count: count) { target in
            bytes.withUnsafeBytes { source in
                if let from = source.baseAddress, let to = target.baseAddress { to.copyMemory(from: from, byteCount: min(count, source.count)) }
            }
        }
    }

    /// Fresh random bytes written straight into owned memory (entropy for `begin_*`, nonce seeds, new keys).
    public static func random(count: Int) throws -> SecretBytes {
        try SecretBytes(count: count) { buffer in
            guard let address = buffer.baseAddress else { return }
            let status = SecRandomCopyBytes(kSecRandomDefault, buffer.count, address)
            guard status == errSecSuccess else { throw KeyError.randomGenerationFailed(status) }
        }
    }

    deinit {
        if let base {
            _ = memset_s(base, count, 0, count)
            base.deallocate()
        }
    }

    /// Reads the bytes in place. The buffer must not escape `body`.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try withExtendedLifetime(self) { try body(UnsafeRawBufferPointer(start: base, count: count)) }
    }

    /// Lends the bytes as a `Data` that refers to this memory without copying it, for one call into an export.
    /// The `Data` must not escape `body` (nor be mutated): it does not own the memory, which is zeroed and freed
    /// when this object goes.
    public func withUnsafeData<R>(_ body: (Data) throws -> R) rethrows -> R {
        try withExtendedLifetime(self) {
            guard let base, count > 0 else { return try body(Data()) }
            return try body(Data(bytesNoCopy: base, count: count, deallocator: .none))
        }
    }

    /// Compares in time that depends only on the lengths.
    public func constantTimeEquals(_ other: SecretBytes) -> Bool {
        guard count == other.count else { return false }
        return withUnsafeBytes { a in
            other.withUnsafeBytes { b in
                var difference: UInt8 = 0
                for index in 0..<count { difference |= a[index] ^ b[index] }
                return difference == 0
            }
        }
    }
}

extension SecretBytes: ContiguousBytes {}

extension SecretBytes: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "SecretBytes(\(count) bytes, redacted)" }
    public var debugDescription: String { description }
}

/// Lends several secrets at once for one export call (`finish_unlock_slot` takes a list).
public func withUnsafeData<R>(_ secrets: [SecretBytes], _ body: ([Data]) throws -> R) throws -> R {
    func lend(_ index: Int, _ lent: [Data]) throws -> R {
        guard index < secrets.count else { return try body(lent) }
        return try secrets[index].withUnsafeData { try lend(index + 1, lent + [$0]) }
    }
    return try lend(0, [])
}

/// Fresh entropy for one export call: generated into owned memory, lent for `body`, zeroed after.
/// The engine wants exactly 32, 64 or 96 bytes (docs/bindings-05.md §5).
public func withEntropy<R>(_ count: Int, _ body: (Data) throws -> R) throws -> R {
    try SecretBytes.random(count: count).withUnsafeData(body)
}
