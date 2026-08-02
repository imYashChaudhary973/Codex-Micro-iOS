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
    .library(name: "CompanionCrypto", targets: ["CompanionCrypto"]),
    .library(name: "CompanionProtocol", targets: ["CompanionProtocol"]),
    .library(name: "MacBridgeCore", targets: ["MacBridgeCore"]),
    .library(name: "MacBridgeServer", targets: ["MacBridgeServer"]),
    .executable(name: "codex-micro-spike", targets: ["CodexMicroSpike"]),
    .executable(name: "codex-micro-bridge", targets: ["CodexMicroBridge"]),
  ],
  dependencies: [
    // ADR §4 pins: swift-certificates 1.19.4 resolves the authorized
    // transitives swift-crypto 4.5.1 and swift-asn1 1.7.1. swift-nio and
    // swift-nio-transport-services are adopted at Step 2.7, not here.
    .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.19.4")
  ],
  targets: [
    .target(name: "CodexAppServer"),
    .target(name: "CompanionProtocol"),
    .target(
      name: "CompanionCrypto",
      dependencies: ["CompanionProtocol"]
    ),
    .target(
      name: "MacBridgeCore",
      dependencies: ["CodexAppServer", "CompanionProtocol"],
      linkerSettings: [
        .linkedFramework("LocalAuthentication"),
        .linkedFramework("Security"),
        .linkedLibrary("sqlite3"),
      ]
    ),
    .target(
      name: "MacBridgeServer",
      dependencies: [
        "CompanionCrypto",
        "CompanionProtocol",
        .product(name: "X509", package: "swift-certificates"),
      ],
      linkerSettings: [
        .linkedFramework("Security")
      ]
    ),
    .executableTarget(
      name: "CodexMicroSpike",
      dependencies: ["CodexAppServer", "MacBridgeCore"]
    ),
    .executableTarget(
      name: "CodexMicroBridge",
      dependencies: ["CompanionProtocol", "MacBridgeCore"]
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
      name: "CompanionCryptoTests",
      dependencies: ["CompanionCrypto", "CompanionProtocol"]
    ),
    .testTarget(
      name: "MacBridgeCoreTests",
      dependencies: ["CompanionProtocol", "MacBridgeCore", "CodexTestSupport"]
    ),
    .testTarget(
      name: "MacBridgeServerTests",
      dependencies: [
        "CompanionCrypto",
        "CompanionProtocol",
        "MacBridgeServer",
        .product(name: "X509", package: "swift-certificates"),
      ]
    ),
  ]
)
