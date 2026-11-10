// The same WasmKit code is called from a macOS CLI and from iOS Simulator XCTest.
// WasmKit 0.4.2, MIT. Package requires Swift tools 6.3; CI records actual compiler.
import Foundation
import CryptoKit
import WasmKit
#if canImport(Darwin)
import Darwin
#endif

public struct SpikeMeasurement: Encodable {
    public let host: String
    public let wasm_sha256: String
    public let build_configuration: String
    public let memory_reporting: String
    public let operations: Int
    public let parse_ms: Double
    public let instantiate_ms: Double
    public let apply_ms: Double
    public let ms_per_op: Double
    public let state_bytes: Int
    public let peak_linear_memory_bytes: Int
    public let peak_rss_bytes: Int64?
    public let state_first_difference: String?
    public let query_first_difference: String?
    public var byte_equal: Bool { state_first_difference == nil && query_first_difference == nil }

    private enum CodingKeys: String, CodingKey {
        case host, wasm_sha256, build_configuration, memory_reporting,
             operations, parse_ms, instantiate_ms, apply_ms, ms_per_op,
             state_bytes, peak_linear_memory_bytes, peak_rss_bytes,
             state_first_difference, query_first_difference, byte_equal
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(host, forKey: .host)
        try container.encode(wasm_sha256, forKey: .wasm_sha256)
        try container.encode(build_configuration, forKey: .build_configuration)
        try container.encode(memory_reporting, forKey: .memory_reporting)
        try container.encode(operations, forKey: .operations)
        try container.encode(parse_ms, forKey: .parse_ms)
        try container.encode(instantiate_ms, forKey: .instantiate_ms)
        try container.encode(apply_ms, forKey: .apply_ms)
        try container.encode(ms_per_op, forKey: .ms_per_op)
        try container.encode(state_bytes, forKey: .state_bytes)
        try container.encode(peak_linear_memory_bytes, forKey: .peak_linear_memory_bytes)
        try container.encodeIfPresent(peak_rss_bytes, forKey: .peak_rss_bytes)
        try container.encodeIfPresent(state_first_difference, forKey: .state_first_difference)
        try container.encodeIfPresent(query_first_difference, forKey: .query_first_difference)
        try container.encode(byte_equal, forKey: .byte_equal)
    }
}

public struct SpikeProbe: Codable {
    public let passed: Bool
    public let wasm_sha256: String
    public let min_success_budget: UInt64?
    public let failed_budget: UInt64?
    public let remaining_at_success: UInt64?
    public let remaining_at_failure: UInt64?
    public let failure: String?
}

public enum SpikeError: Error, CustomStringConvertible {
    case message(String)
    public var description: String {
        switch self { case .message(let message): return message }
    }
}

private func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
private func millis(_ start: UInt64) -> Double { Double(now() - start) / 1_000_000.0 }

private func rssBytes() -> Int64? {
    #if canImport(Darwin)
    var usage = rusage()
    guard getrusage(RUSAGE_SELF, &usage) == 0 else { return nil }
    // Darwin's ru_maxrss is measured in bytes; on Linux it is KiB.
    return Int64(usage.ru_maxrss)
    #else
    return nil
    #endif
}

public enum ModuleSpike {
    #if DEBUG
    public static let buildConfiguration = "debug"
    #else
    public static let buildConfiguration = "release"
    #endif

    public static func sha256(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    public static func firstDifference(_ expected: Data, _ got: Data) -> String? {
        let a = Array(expected), b = Array(got)
        for i in 0..<min(a.count, b.count) {
            if a[i] != b[i] {
                return "byte \(i): expected \(a[i]), got \(b[i])"
            }
        }
        return a.count == b.count ? nil : "length: expected \(a.count), got \(b.count)"
    }

    public static func operations(_ data: Data) -> [Data] {
        // Native Rust emits canonical JSON with one operation per line.
        data.split(separator: 0x0a).map { Data($0) }
    }

    public static func run(
        wasmBytes: Data,
        operations: [Data],
        count: Int,
        expectedState: Data,
        expectedQuery: Data,
        host: String
    ) throws -> SpikeMeasurement {
        guard count > 0 && operations.count >= count else {
            throw SpikeError.message("not enough fixture operations")
        }
        let started = now()
        let module = try parseWasm(bytes: Array(wasmBytes))
        let parseMs = millis(started)
        let startInstance = now()
        let guest = try Guest(module: module, nativeFuel: false)
        let instantiateMs = millis(startInstance)
        var state = try guest.initial()
        var peakLinear = guest.memory.byteCount
        let startApply = now()
        for i in 0..<count {
            state = try guest.apply(state, operations[i])
            if (i & 127) == 0 { peakLinear = max(peakLinear, guest.memory.byteCount) }
        }
        let applyMs = millis(startApply)
        peakLinear = max(peakLinear, guest.memory.byteCount)
        let query = try guest.query(state, name: "noteCounts", args: Data("{}".utf8))
        return SpikeMeasurement(
            host: host, wasm_sha256: sha256(wasmBytes),
            build_configuration: buildConfiguration,
            memory_reporting: "guest linear memory sampled at start/128-op intervals/end; Darwin ru_maxrss is process-lifetime peak, not per-case",
            operations: count,
            parse_ms: parseMs, instantiate_ms: instantiateMs,
            apply_ms: applyMs, ms_per_op: applyMs / Double(count),
            state_bytes: state.count, peak_linear_memory_bytes: peakLinear,
            peak_rss_bytes: rssBytes(),
            state_first_difference: firstDifference(expectedState, state),
            query_first_difference: firstDifference(expectedQuery, query)
        )
    }

    /// Prove a numeric cut-off for either *WasmKit's own* fuel or the WAT
    /// rewriting's internal fuel. Only the latter is comparable to JS hosts.
    public static func probe(
        wasmBytes: Data,
        firstOperation: Data,
        builtinFuel: Bool
    ) throws -> SpikeProbe {
        let module = try parseWasm(bytes: Array(wasmBytes))
        func trial(_ budget: UInt64) throws -> (Bool, UInt64, String?) {
            let guest = try Guest(module: module, nativeFuel: builtinFuel)
            if builtinFuel {
                guest.store.fuel = Fuel(remaining: 1_000_000_000)
            } else {
                try guest.invokeVoid("fuel_reset", [.i64(1_000_000_000)])
            }
            let initial = try guest.initial()
            let statePointer = try guest.write(initial)
            let operationPointer = try guest.write(firstOperation)
            if builtinFuel {
                guest.store.fuel = Fuel(remaining: budget)
            } else {
                try guest.invokeVoid("fuel_reset", [.i64(budget)])
            }
            do {
                let packed = try guest.invoke(
                    "apply", [.i32(statePointer), .i32(UInt32(initial.count)),
                              .i32(operationPointer), .i32(UInt32(firstOperation.count))]
                )
                guard case .i64(let raw) = packed, raw != 0 else {
                    throw SpikeError.message("module returned a null result")
                }
                let left = try guest.remainingFuel(builtin: builtinFuel)
                return (true, left, nil)
            } catch {
                return (false, (try? guest.remainingFuel(builtin: builtinFuel)) ?? 0, String(describing: error))
            }
            // Always discard the store after a trap. It may hold leaked buffers.
        }

        var high: UInt64 = 1
        var highTrial = try trial(high)
        while !highTrial.0 && high < 1_000_000_000 {
            high *= 2
            highTrial = try trial(high)
        }
        if !highTrial.0 {
            return SpikeProbe(passed: false, wasm_sha256: sha256(wasmBytes), min_success_budget: nil,
                              failed_budget: high, remaining_at_success: nil,
                              remaining_at_failure: highTrial.1, failure: highTrial.2)
        }
        var low: UInt64 = 0
        while high - low > 1 {
            let middle = low + (high - low) / 2
            if try trial(middle).0 { high = middle } else { low = middle }
        }
        let succeeds = try trial(high), fails = try trial(high - 1)
        return SpikeProbe(
            passed: succeeds.0 && !fails.0,
            wasm_sha256: sha256(wasmBytes),
            min_success_budget: high, failed_budget: high-1,
            remaining_at_success: succeeds.1, remaining_at_failure: fails.1,
            failure: fails.2
        )
    }
}

private final class Guest {
    let store: Store
    let instance: Instance
    let memory: Memory

    init(module: Module, nativeFuel: Bool) throws {
        let engine = Engine(configuration: EngineConfiguration(fuelMetering: nativeFuel))
        let newStore = Store(engine: engine)
        let newInstance = try module.instantiate(store: newStore)
        guard let newMemory = newInstance.exports[memory: "memory"] else {
            throw SpikeError.message("WasmKit module lacks memory export")
        }
        for name in ["alloc", "release", "apply", "query", "initial"] {
            guard newInstance.exports[function: name] != nil else {
                throw SpikeError.message("WasmKit missing export \(name)")
            }
        }
        store = newStore
        instance = newInstance
        memory = newMemory
    }

    func invoke(_ name: String, _ arguments: [Value] = []) throws -> Value {
        guard let fn = instance.exports[function: name] else {
            throw SpikeError.message("missing export \(name)")
        }
        guard let result = try fn(arguments).first else {
            throw SpikeError.message("no return from \(name)")
        }
        return result
    }

    func invokeVoid(_ name: String, _ arguments: [Value]) throws {
        guard let fn = instance.exports[function: name] else {
            throw SpikeError.message("missing export \(name)")
        }
        _ = try fn(arguments)
    }

    func write(_ bytes: Data) throws -> UInt32 {
        guard bytes.count <= 16 * 1024 * 1024 else {
            throw SpikeError.message("input exceeds 16 MiB")
        }
        guard case .i32(let ptr) = try invoke("alloc", [.i32(UInt32(bytes.count))]),
              ptr != 0, UInt64(ptr) + UInt64(bytes.count) <= UInt64(memory.byteCount) else {
            throw SpikeError.message("guest allocation out of bounds")
        }
        memory.withUnsafeMutableBufferPointer(offset: UInt(ptr), count: bytes.count) { destination in
            destination.copyBytes(from: bytes)
        }
        return ptr
    }

    private func readPacked(_ value: Value) throws -> Data {
        guard case .i64(let packed) = value, packed != 0 else {
            throw SpikeError.message("guest returned null result")
        }
        let ptr = UInt32(truncatingIfNeeded: packed)
        let len = Int(packed >> 32)
        guard len > 0, len <= 16 * 1024 * 1024,
              UInt64(ptr) + UInt64(len) <= UInt64(memory.byteCount) else {
            throw SpikeError.message("guest result out of bounds")
        }
        let bytes = memory.withUnsafeBufferPointer(offset: UInt(ptr), count: len) {
            Data($0)
        }
        try invokeVoid("release", [.i32(ptr), .i32(UInt32(len))])
        return bytes
    }

    func initial() throws -> Data {
        try readPacked(invoke("initial"))
    }

    private func call(_ name: String, _ arguments: [Data]) throws -> Data {
        var allocations: [(UInt32, Int)] = []
        defer {
            for (ptr, len) in allocations {
                try? invokeVoid("release", [.i32(ptr), .i32(UInt32(len))])
            }
        }
        var args: [Value] = []
        for argument in arguments {
            let ptr = try write(argument)
            allocations.append((ptr, argument.count))
            args.append(contentsOf: [.i32(ptr), .i32(UInt32(argument.count))])
        }
        return try readPacked(invoke(name, args))
    }

    func apply(_ state: Data, _ op: Data) throws -> Data {
        try call("apply", [state, op])
    }

    func query(_ state: Data, name: String, args: Data) throws -> Data {
        try call("query", [state, Data(name.utf8), args])
    }

    func remainingFuel(builtin: Bool) throws -> UInt64 {
        if builtin { return store.fuel?.remaining ?? 0 }
        guard case .i64(let value) = try invoke("fuel_left") else {
            throw SpikeError.message("bad fuel_left signature")
        }
        return value
    }
}
