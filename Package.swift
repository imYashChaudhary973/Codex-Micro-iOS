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
    // The complete, closed ADR §4 pin set. These three direct pins resolve
    // exactly the five authorized transitives (swift-atomics 1.3.1,
    // swift-collections 1.6.0, swift-system 1.7.5, swift-crypto 4.5.1,
    // swift-asn1 1.7.1). No other repository may be declared or resolved.
    .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.19.4"),
    .package(url: "https://github.com/apple/swift-nio.git", exact: "2.101.3"),
    .package(url: "https://github.com/apple/swift-nio-transport-services.git", exact: "1.28.0"),
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
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOWebSocket", package: "swift-nio"),
        .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
      ],
      linkerSettings: [
        .linkedFramework("Security"),
        .linkedFramework("SystemConfiguration"),
      ]
    ),
    .executableTarget(
      name: "CodexMicroSpike",
      dependencies: ["CodexAppServer", "MacBridgeCore"]
    ),
    .executableTarget(
      name: "CodexMicroBridge",
      dependencies: [
        "CompanionCrypto", "CompanionProtocol", "MacBridgeCore", "MacBridgeServer",
      ]
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
      name: "CodexMicroBridgeTests",
      dependencies: [
        "CodexMicroBridge", "CompanionCrypto", "CompanionProtocol", "MacBridgeCore",
        "MacBridgeServer",
      ]
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
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOEmbedded", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOWebSocket", package: "swift-nio"),
      ]
    ),
  ]
)
