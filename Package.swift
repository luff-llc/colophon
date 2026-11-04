// swift-tools-version: 6.0
import PackageDescription

// Colophon: a user-owned data standard. Each layer is its own module so a client takes only
// what it needs: a verifier needs Core and Authority; a storage provider needs Store; an app adds
// Replica and the domain modules it shows.
let package = Package(name: "Colophon", platforms: [.macOS(.v14), .iOS(.v17), .visionOS("26.0")], products: [
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
  .target(name: "ColophonCore"),
  .target(name: "ColophonStore", dependencies: ["ColophonCore"]),
  .target(name: "ColophonAuthority", dependencies: ["ColophonCore", "ColophonStore"]),
  .target(name: "ColophonReplica", dependencies: ["ColophonCore", "ColophonStore", "ColophonAuthority"]),
  .target(name: "ColophonSaved", dependencies: ["ColophonReplica"]),
  .target(name: "ColophonBooks", dependencies: ["ColophonReplica"]),
  .target(name: "ColophonListening", dependencies: ["ColophonReplica"]),
  .target(name: "ColophonNotes", dependencies: ["ColophonReplica", "ColophonListening"]),
  .target(name: "ColophonMCP", dependencies: ["ColophonReplica"]),
  .executableTarget(name: "colophon", dependencies: ["ColophonMCP", "ColophonSaved", "ColophonBooks", "ColophonListening",
    "ColophonNotes"]),
  .testTarget(name: "ColophonTests", dependencies: ["ColophonCore", "ColophonStore", "ColophonAuthority", "ColophonReplica",
    "ColophonSaved", "ColophonBooks", "ColophonListening", "ColophonNotes", "ColophonMCP"]),
])
