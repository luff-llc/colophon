// swift-tools-version: 6.0
import PackageDescription

// The Rust-backed 0.2 SDK. The independent 0.1 package lives in reference/swift.
let package = Package(name: "ColophonSDK", platforms: [.macOS(.v14), .iOS(.v17), .visionOS("26.0")], products: [
  .library(name: "ColophonFFI", targets: ["ColophonFFI"]),
  .library(name: "ColophonKit", targets: ["ColophonKit"]),
  .library(name: "ColophonKitStorage", targets: ["ColophonKitStorage"]),
  .library(name: "ColophonSession", targets: ["ColophonSession"]),
  .library(name: "ColophonSessionUI", targets: ["ColophonSessionUI"]),
  .library(name: "ColophonBooksKit", targets: ["ColophonBooksKit"]),
  .library(name: "ColophonListeningKit", targets: ["ColophonListeningKit"]),
  .library(name: "ColophonSavedKit", targets: ["ColophonSavedKit"]),
  .library(name: "ColophonNotesKit", targets: ["ColophonNotesKit"]),
  .library(name: "ColophonMigration", targets: ["ColophonMigration"]),
], targets: [
  .target(name: "ColophonMigration", dependencies: ["ColophonSession"], path: "swift/Sources/ColophonMigration"),
  .testTarget(name: "ColophonMigrationTests", dependencies: ["ColophonMigration"], path: "swift/Tests/ColophonMigrationTests"),
  .target(name: "ColophonKitStorage", path: "swift/Sources/ColophonKitStorage"),
  .target(name: "ColophonBooksKit", dependencies: ["ColophonSession"], path: "swift/Sources/ColophonBooksKit"),
  .target(name: "ColophonListeningKit", dependencies: ["ColophonSession"], path: "swift/Sources/ColophonListeningKit"),
  .target(name: "ColophonSavedKit", dependencies: ["ColophonSession"], path: "swift/Sources/ColophonSavedKit"),
  .target(name: "ColophonNotesKit", dependencies: ["ColophonSession"], path: "swift/Sources/ColophonNotesKit"),
  .target(name: "ColophonSession", dependencies: ["ColophonKit", "ColophonKitStorage"], path: "swift/Sources/ColophonSession"),
  .target(name: "ColophonSessionUI", dependencies: ["ColophonSession"], path: "swift/Sources/ColophonSessionUI"),
  .testTarget(name: "ColophonSessionUITests", dependencies: ["ColophonSessionUI"], path: "swift/Tests/ColophonSessionUITests"),
  .testTarget(name: "ColophonDomainKitTests", dependencies: ["ColophonBooksKit", "ColophonListeningKit", "ColophonSavedKit", "ColophonNotesKit"], path: "swift/Tests/ColophonDomainKitTests"),
  .testTarget(name: "ColophonSessionTests", dependencies: ["ColophonSession", "ColophonKitStorage"], path: "swift/Tests/ColophonSessionTests"),
  .binaryTarget(name: "ColophonFFI", path: "sdk/apple/ColophonFFI.xcframework"),
  .target(name: "ColophonKit", dependencies: ["ColophonFFI"], path: "swift/Sources/ColophonKit",
          exclude: ["Generated/ColophonFFI.h", "Generated/ColophonFFI.modulemap"],
          linkerSettings: [.linkedLibrary("resolv")]),
  .testTarget(name: "ColophonKitTests", dependencies: ["ColophonKit"], path: "swift/Tests/ColophonKitTests"),
], swiftLanguageModes: [.v6])
