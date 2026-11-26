// swift-tools-version: 6.0
import PackageDescription

// An application's view of the 0.6 hosts: this package depends on the ColophonSDK package the way an app does, so it
// sees only the products' public API. HostsClient must compile and its test must open a host; each snippet in
// Refused/ must fail to compile when added to HostsClient (scripts/test-swift-hosts.sh checks both).
let package = Package(name: "HostsClient", platforms: [.macOS(.v14), .iOS(.v17)], dependencies: [
  .package(name: "ColophonSDK", path: "../.."),
], targets: [
  .target(name: "HostsClient", dependencies: [
    .product(name: "ColophonHosts", package: "ColophonSDK"), .product(name: "ColophonSession", package: "ColophonSDK"),
    .product(name: "ColophonListeningKit", package: "ColophonSDK"),
  ], path: "Sources/HostsClient"),
  .testTarget(name: "HostsClientTests", dependencies: ["HostsClient"], path: "Tests/HostsClientTests"),
], swiftLanguageModes: [.v6])
