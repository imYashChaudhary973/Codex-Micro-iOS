import CompanionCrypto
import CompanionProtocol
import Foundation
import MacBridgeCore
import MacBridgeServer
import XCTest

@testable import CodexMicroBridge

/// The user-facing surface: the redacted metrics a menu shows and the signed
/// app's local-network keys.
final class BridgeControlSurfaceTests: XCTestCase {

  // MARK: - Redacted metrics

  func testTheIdleSnapshotIsAllZeroAndOff() {
    let metrics = BridgeConnectionMetrics.idle

    XCTAssertEqual(metrics.lanState, .disabled)
    XCTAssertFalse(metrics.isAdvertising)
    XCTAssertEqual(metrics.activeConnections, 0)
    XCTAssertEqual(metrics.pairedDevices, 0)
  }

  func testNegativeCountsAreClampedRatherThanShown() {
    let metrics = BridgeConnectionMetrics(
      lanState: .disabled,
      isAdvertising: false,
      activeConnections: -5,
      unauthenticatedConnections: -1,
      pairedDevices: -2,
      observingDevices: -3,
      deliveredChanges: -4,
      retentionGaps: -6
    )

    XCTAssertEqual(metrics.activeConnections, 0)
    XCTAssertEqual(metrics.unauthenticatedConnections, 0)
    XCTAssertEqual(metrics.pairedDevices, 0)
    XCTAssertEqual(metrics.observingDevices, 0)
    XCTAssertEqual(metrics.deliveredChanges, 0)
    XCTAssertEqual(metrics.retentionGaps, 0)
  }

  /// A metrics line is glanced at, screenshotted, and pasted into issues, so
  /// it must carry nothing that would matter in a screenshot.
  func testTheRenderedLinesCarryNoAddressNameOrIdentifier() {
    let metrics = BridgeConnectionMetrics(
      lanState: .enabled(host: "192.168.1.20", port: 8443),
      isAdvertising: true,
      activeConnections: 2,
      unauthenticatedConnections: 1,
      pairedDevices: 3,
      observingDevices: 1,
      deliveredChanges: 42,
      retentionGaps: 0
    )

    let rendered = metrics.menuLines.joined(separator: "\n")

    for forbidden in [
      "192.168.1.20", "8443", ProcessInfo.processInfo.hostName, NSUserName(),
    ] where !forbidden.isEmpty {
      XCTAssertFalse(rendered.contains(forbidden), "leaked \(forbidden)")
    }
    XCTAssertTrue(rendered.contains("LAN: on"))
  }

  func testEveryLanStateHasAClosedDescription() {
    let states: [BridgeLANState] = [
      .disabled, .enabling, .enabled(host: "10.0.0.1", port: 1),
      .disabling, .failed(.startupDenied),
    ]

    let described = states.map(BridgeConnectionMetrics.describe)

    XCTAssertEqual(
      described, ["off", "starting", "on", "stopping", "failed (startupDenied)"])
    for reason in BridgeLANFailure.allCases {
      let text = BridgeConnectionMetrics.describe(.failed(reason))
      XCTAssertTrue(text.contains(reason.rawValue), reason.rawValue)
    }
  }

  // MARK: - The signed app's local-network keys

  /// ADR §12 requires both keys on macOS 15+, and the allowlist must match
  /// the service the bridge actually publishes.
  func testTheInfoPlistCarriesTheLocalNetworkKeys() throws {
    let url = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("Sources/CodexMicroBridge/Info.plist")
    let data = try Data(contentsOf: url)
    let plist =
      try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] ?? [:]

    XCTAssertNotNil(plist["NSLocalNetworkUsageDescription"] as? String)
    let services = try XCTUnwrap(plist["NSBonjourServices"] as? [String])
    XCTAssertEqual(services, [ListenerBonjourRecord.serviceType])
    XCTAssertEqual(plist["LSUIElement"] as? Bool, true)
  }

}
