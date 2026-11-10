import Foundation
import XCTest
import ModuleSpikeShared

/// Run by xcodebuild on a booted iOS Simulator. Not a real iPhone measurement.
/// Build script copies the WASM and native expected bytes into Resources.
final class ModuleSpikeSimulatorTests: XCTestCase {
    private func resource(_ name: String, _ ext: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Resources") else {
            throw SpikeError.message("missing bundled resource \(name).\(ext): run prepare-ios-resources.sh first")
        }
        return try Data(contentsOf: url)
    }

    func testSameBytesAcrossNativeAndSimulator() throws {
        let wasm = try resource("notes", "wasm")
        let operations = ModuleSpike.operations(try resource("operations", "jsonl"))
        for n in [1, 1000, 10000] {
            let measurement = try ModuleSpike.run(
                wasmBytes: wasm, operations: operations, count: n,
                expectedState: resource("expected-\(n)", "json"),
                expectedQuery: resource("expected-query-\(n)", "json"),
                host: "wasmkit-ios-simulator"
            )
            let data = try JSONEncoder().encode(measurement)
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("ios-\(n).json")
            try data.write(to: file)
            print("SIMULATOR MEASUREMENT \(String(data: data, encoding: .utf8) ?? "")")
            XCTAssertTrue(measurement.byte_equal, "first difference: \(measurement.state_first_difference ?? measurement.query_first_difference ?? "unknown")")
            XCTAssertLessThanOrEqual(measurement.peak_linear_memory_bytes, 64 * 1024 * 1024)
        }
    }

    func testInsideModuleFuelFailsClosed() throws {
        let wasm = try resource("notes-metered", "wasm")
        let operations = ModuleSpike.operations(try resource("operations", "jsonl"))
        let result = try ModuleSpike.probe(wasmBytes: wasm, firstOperation: operations[0], builtinFuel: false)
        XCTAssertTrue(result.passed)
        print("SIMULATOR METER \(String(data: try JSONEncoder().encode(result), encoding: .utf8) ?? "")")
    }
}
