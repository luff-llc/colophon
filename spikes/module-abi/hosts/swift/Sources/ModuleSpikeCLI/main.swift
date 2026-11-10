import Foundation
import ModuleSpikeShared

func read(_ path: String) throws -> Data { try Data(contentsOf: URL(fileURLWithPath: path)) }
func writeJSON<T: Encodable>(_ value: T, to path: String) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    var data = try encoder.encode(value)
    data.append(0x0a)
    try data.write(to: URL(fileURLWithPath: path))
}

do {
    let args = Array(CommandLine.arguments.dropFirst())
    guard args.count >= 2 else {
        throw SpikeError.message("usage: module-spike-swift module.wasm OUT_DIRECTORY [metered.wasm]")
    }
    let wasm = try read(args[0])
    let root = args[1]
    let operations = ModuleSpike.operations(try read(root + "/operations.jsonl"))
    try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
    for count in [1, 1000, 10000] {
        let measurement = try ModuleSpike.run(
            wasmBytes: wasm, operations: operations, count: count,
            expectedState: read(root + "/expected-\(count).json"),
            expectedQuery: read(root + "/expected-query-\(count).json"),
            host: "wasmkit-macos-cli"
        )
        try writeJSON(measurement, to: root + "/swift-\(count).json")
        print("wasmkit: \(count) ops, equal=\(measurement.byte_equal), \(measurement.ms_per_op) ms/op")
        if !measurement.byte_equal { exit(1) }
    }
    let builtin = try ModuleSpike.probe(wasmBytes: wasm, firstOperation: operations[0], builtinFuel: true)
    try writeJSON(builtin, to: root + "/swift-builtin-fuel.json")
    print("wasmkit native fuel: \(builtin)")
    if args.count > 2 {
        let metered = try read(args[2])
        let rewrite = try ModuleSpike.probe(wasmBytes: metered, firstOperation: operations[0], builtinFuel: false)
        try writeJSON(rewrite, to: root + "/swift-meter.json")
        print("rewritten fuel: \(rewrite)")
    }
} catch {
    fputs("module-spike-swift: \(error)\n", stderr)
    exit(1)
}
