import Foundation
import MacBridgeCore
import MacBridgeServer

/// The redacted connection metrics the Mac menu may show (plan Step 2.13).
///
/// **Counts only.** Every field is a non-negative integer or a closed
/// enumeration case. There is no endpoint, address, host name, device
/// identifier, fingerprint, project, thread, or timestamp — the type has no
/// field that could carry one, which is what makes the diagnostics
/// content-free by construction rather than by filtering (plan §2
/// invariant 19).
///
/// This is deliberately weaker than what the Mac user could learn elsewhere:
/// device administration has its own authenticated view. A metrics line in a
/// menu is glanced at, screenshotted, and pasted into issues, so it carries
/// nothing that would matter in a screenshot.
public struct BridgeConnectionMetrics: Equatable, Sendable {
  /// Whether LAN access is on, off, or failed — the closed control state.
  public let lanState: BridgeLANState
  /// Whether a Bonjour record is currently advertised.
  public let isAdvertising: Bool
  /// Connections currently accepted, authenticated or not.
  public let activeConnections: Int
  /// Of those, the ones still unauthenticated.
  public let unauthenticatedConnections: Int
  /// Devices holding a live grant.
  public let pairedDevices: Int
  /// Devices with an open observation subscription.
  public let observingDevices: Int
  /// Journal changes the pump has delivered to the broker this process.
  public let deliveredChanges: Int
  /// Retention gaps the pump recorded this process.
  public let retentionGaps: Int

  public init(
    lanState: BridgeLANState,
    isAdvertising: Bool,
    activeConnections: Int,
    unauthenticatedConnections: Int,
    pairedDevices: Int,
    observingDevices: Int,
    deliveredChanges: Int,
    retentionGaps: Int
  ) {
    self.lanState = lanState
    self.isAdvertising = isAdvertising
    self.activeConnections = max(0, activeConnections)
    self.unauthenticatedConnections = max(0, unauthenticatedConnections)
    self.pairedDevices = max(0, pairedDevices)
    self.observingDevices = max(0, observingDevices)
    self.deliveredChanges = max(0, deliveredChanges)
    self.retentionGaps = max(0, retentionGaps)
  }

  /// The empty snapshot: LAN off and nothing connected.
  public static let idle = BridgeConnectionMetrics(
    lanState: .disabled,
    isAdvertising: false,
    activeConnections: 0,
    unauthenticatedConnections: 0,
    pairedDevices: 0,
    observingDevices: 0,
    deliveredChanges: 0,
    retentionGaps: 0
  )

  /// One line per metric, for a menu.
  ///
  /// Rendering lives here rather than in the view so the guarantee above is
  /// testable: a test can assert the rendered text contains no address, name,
  /// or identifier, and that assertion covers what the user actually sees.
  public var menuLines: [String] {
    [
      "LAN: \(Self.describe(lanState))",
      "Advertising: \(isAdvertising ? "yes" : "no")",
      "Connections: \(activeConnections) (\(unauthenticatedConnections) unauthenticated)",
      "Paired devices: \(pairedDevices)",
      "Observing: \(observingDevices)",
      "Changes delivered: \(deliveredChanges)",
      "Retention gaps: \(retentionGaps)",
    ]
  }

  /// The closed description of a LAN state.
  ///
  /// Deliberately does **not** include the bound host or port even though
  /// ``BridgeLANState/enabled(host:port:)`` carries them: the user learns the
  /// endpoint from the pairing QR, which is shown deliberately and briefly,
  /// not from a status line that lives in a screenshot.
  static func describe(_ state: BridgeLANState) -> String {
    switch state {
    case .disabled: return "off"
    case .enabling: return "starting"
    case .enabled: return "on"
    case .disabling: return "stopping"
    case .failed(let reason): return "failed (\(reason.rawValue))"
    }
  }
}
