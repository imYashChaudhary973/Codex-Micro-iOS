// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "Phase2Transport",
  platforms: [
    .macOS(.v14)
  ],
  products: [
    .library(name: "Phase2Transport", targets: ["Phase2Transport"])
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.19.4")
  ],
  targets: [
    .target(
      name: "Phase2Transport",
      dependencies: [
        .product(name: "X509", package: "swift-certificates")
      ]
    ),
    .testTarget(
      name: "Phase2TransportTests",
      dependencies: ["Phase2Transport"]
    ),
  ]
)
