// swift-tools-version: 6.0
import PackageDescription

// Colophon: a user-owned data standard. Each layer is its own module so a client takes only
// what it needs: a verifier needs Core and Authority; a storage provider needs Store; an app adds
// Replica and the domain modules it shows.
let package = Package(name: "Colophon", platforms: [.macOS(.v14), .iOS(.v17), .visionOS("26.0")], products: [
  .library(name: "ColophonMigration", targets: ["ColophonMigration"]),
  .library(name: "ColophonKitStorage", targets: ["ColophonKitStorage"]),
  .library(name: "ColophonSession", targets: ["ColophonSession"]),
  .library(name: "ColophonKit", targets: ["ColophonKit"]),
  .library(name: "ColophonCore", targets: ["ColophonCore"]),
  .library(name: "ColophonStore", targets: ["ColophonStore"]),
  .library(name: "ColophonAuthority", targets: ["ColophonAuthority"]),
  .library(name: "ColophonReplica", targets: ["ColophonReplica"]),
  .library(name: "ColophonSaved", targets: ["ColophonSaved"]),
  .library(name: "ColophonBooks", targets: ["ColophonBooks"]),
  .library(name: "ColophonListening", targets: ["ColophonListening"]),
  .library(name: "ColophonNotes", targets: ["ColophonNotes"]),
  .library(name: "ColophonMCP", targets: ["ColophonMCP"]),
  .executable(name: "colophon", targets: ["colophon"]),
], targets: [
  .target(name: "ColophonMigration", dependencies: ["ColophonSession", "ColophonCore", "ColophonStore", "ColophonAuthority", "ColophonReplica", "ColophonBooks", "ColophonListening", "ColophonSaved", "ColophonNotes"], path: "swift/Sources/ColophonMigration"),
  .testTarget(name: "ColophonMigrationTests", dependencies: ["ColophonMigration"], path: "swift/Tests/ColophonMigrationTests"),
  .target(name: "ColophonKitStorage", path: "swift/Sources/ColophonKitStorage"),
  .target(name: "ColophonSession", dependencies: ["ColophonKit", "ColophonKitStorage"], path: "swift/Sources/ColophonSession"),
  .testTarget(name: "ColophonSessionTests", dependencies: ["ColophonSession", "ColophonKitStorage"], path: "swift/Tests/ColophonSessionTests"),
  .binaryTarget(name: "ColophonFFI", path: "sdk/apple/ColophonFFI.xcframework"),
  .target(name: "ColophonKit", dependencies: ["ColophonFFI"], path: "swift/Sources/ColophonKit",
          exclude: ["Generated/ColophonFFI.h", "Generated/ColophonFFI.modulemap"],
          linkerSettings: [.linkedLibrary("resolv")]),
  .testTarget(name: "ColophonKitTests", dependencies: ["ColophonKit"], path: "swift/Tests/ColophonKitTests"),
  .target(name: "ColophonCore", path: "swift/Sources/ColophonCore"),
  .target(name: "ColophonStore", dependencies: ["ColophonCore"], path: "swift/Sources/ColophonStore"),
  .target(name: "ColophonAuthority", dependencies: ["ColophonCore", "ColophonStore"], path: "swift/Sources/ColophonAuthority"),
  .target(name: "ColophonReplica", dependencies: ["ColophonCore", "ColophonStore", "ColophonAuthority"], path: "swift/Sources/ColophonReplica"),
  .target(name: "ColophonSaved", dependencies: ["ColophonReplica"], path: "swift/Sources/ColophonSaved"),
  .target(name: "ColophonBooks", dependencies: ["ColophonReplica"], path: "swift/Sources/ColophonBooks"),
  .target(name: "ColophonListening", dependencies: ["ColophonReplica"], path: "swift/Sources/ColophonListening"),
  .target(name: "ColophonNotes", dependencies: ["ColophonReplica", "ColophonListening"], path: "swift/Sources/ColophonNotes"),
  .target(name: "ColophonMCP", dependencies: ["ColophonReplica"], path: "swift/Sources/ColophonMCP"),
  .executableTarget(name: "colophon", dependencies: ["ColophonMCP", "ColophonSaved", "ColophonBooks", "ColophonListening",
    "ColophonNotes"], path: "swift/Sources/colophon"),
  .testTarget(name: "ColophonTests", dependencies: ["ColophonCore", "ColophonStore", "ColophonAuthority", "ColophonReplica",
    "ColophonSaved", "ColophonBooks", "ColophonListening", "ColophonNotes", "ColophonMCP"], path: "swift/Tests/ColophonTests"),
], swiftLanguageModes: [.v6])
