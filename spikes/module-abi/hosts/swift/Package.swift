// swift-tools-version:6.3
import PackageDescription

let package = Package(
    name: "ModuleABISpikeHost",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "ModuleSpikeShared", targets: ["ModuleSpikeShared"]),
        .executable(name: "module-spike-swift", targets: ["ModuleSpikeCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftwasm/WasmKit.git", exact: "0.4.2"),
    ],
    targets: [
        .target(name: "ModuleSpikeShared", dependencies: [
            .product(name: "WasmKit", package: "WasmKit"),
        ]),
        .executableTarget(name: "ModuleSpikeCLI", dependencies: ["ModuleSpikeShared"]),
        .testTarget(
            name: "ModuleSpikeSimulatorTests",
            dependencies: ["ModuleSpikeShared"],
            resources: [.copy("Resources")]
        ),
    ]
)
