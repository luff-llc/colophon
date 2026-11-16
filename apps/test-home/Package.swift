// swift-tools-version: 6.0
import PackageDescription

// The local home service for the Colophon test apps: provisions a home slot on the reference relay for a new account
// and answers with the home's signed member request. A development tool for this Mac, never shipped.
let package = Package(name: "ColophonTestHome", platforms: [.macOS(.v14)], dependencies: [
  .package(name: "ColophonSDK", path: "../.."),
], targets: [
  .executableTarget(name: "colophon-test-home", dependencies: [.product(name: "ColophonKit", package: "ColophonSDK")],
                    path: "Sources/colophon-test-home"),
], swiftLanguageModes: [.v6])
