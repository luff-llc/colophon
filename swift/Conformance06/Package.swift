// swift-tools-version: 6.0
import PackageDescription

// The 0.6 session conformance replay from Swift. A separate, test-only package: it links the conformance crate's
// artifact (crates/colophon-conformance, built by scripts/test-swift-hosts.sh into Artifacts/ with its generated Swift in
// Generated/), which the shipped ColophonSDK package neither links nor exports.
let package = Package(name: "ColophonConformance06", platforms: [.macOS(.v14)], targets: [
  .binaryTarget(name: "ColophonConformanceFFI", path: "Artifacts/ColophonConformanceFFI.xcframework"),
  .target(name: "ColophonConformanceBindings", dependencies: ["ColophonConformanceFFI"], path: "Generated",
          exclude: ["colophon_conformanceFFI.h", "colophon_conformanceFFI.modulemap"],
          linkerSettings: [.linkedLibrary("resolv")]),
  .testTarget(name: "ColophonConformanceTests", dependencies: ["ColophonConformanceBindings"], path: "Tests/ColophonConformanceTests"),
], swiftLanguageModes: [.v6])
