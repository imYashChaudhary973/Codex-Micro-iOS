// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "CodexMicro",
  platforms: [
    .macOS(.v14),
    .iOS(.v17),
  ],
  products: [
    .library(name: "CodexAppServer", targets: ["CodexAppServer"]),
    .library(name: "CompanionProtocol", targets: ["CompanionProtocol"]),
    .library(name: "MacBridgeCore", targets: ["MacBridgeCore"]),
    .executable(name: "codex-micro-spike", targets: ["CodexMicroSpike"]),
  ],
  targets: [
    .target(name: "CodexAppServer"),
    .target(name: "CompanionProtocol"),
    .target(
      name: "MacBridgeCore",
      dependencies: ["CodexAppServer", "CompanionProtocol"],
      linkerSettings: [
        .linkedFramework("LocalAuthentication"),
        .linkedFramework("Security"),
        .linkedLibrary("sqlite3"),
      ]
    ),
    .executableTarget(
      name: "CodexMicroSpike",
      dependencies: ["CodexAppServer", "MacBridgeCore"]
    ),
    .target(
      name: "CodexTestSupport",
      dependencies: ["CodexAppServer"]
    ),
    .testTarget(
      name: "CodexAppServerTests",
      dependencies: ["CodexAppServer", "CodexTestSupport"]
    ),
    .testTarget(
      name: "MacBridgeCoreTests",
      dependencies: ["CompanionProtocol", "MacBridgeCore", "CodexTestSupport"]
    ),
  ]
)
