import CompanionProtocol
import Foundation
import MacBridgeCore
import Observation

/// Menu-bar view state derived from assembly updates. All strings shown in
/// the UI are fixed status labels plus counts; no thread or prompt content.
@MainActor
@Observable
final class BridgeStatusModel {
  private(set) var statusText = "Starting…"
  private(set) var symbolName = "circle.dotted"
  private(set) var threadCount = 0
  private(set) var pendingApprovalCount = 0
  /// Redacted connection metrics. Counts and closed states only.
  private(set) var metrics = BridgeConnectionMetrics.idle

  private var assembly: CodexBridgeAssembly?
  private var observationTask: Task<Void, Never>?
  private var lanController: BridgeLANController?
  private var lanTask: Task<Void, Never>?

  /// Whether the LAN control may be used.
  ///
  /// It stays disabled until a controller is attached, so a build with no
  /// listener wired shows the control greyed rather than offering an action
  /// that would do nothing.
  var isLANControlEnabled: Bool {
    lanController != nil && lanTask == nil
  }

  /// The LAN control's label, derived from the closed state.
  var lanButtonTitle: String {
    switch metrics.lanState {
    case .disabled, .failed: return "Enable LAN Access"
    case .enabling: return "Enabling…"
    case .enabled: return "Disable LAN Access"
    case .disabling: return "Disabling…"
    }
  }

  /// Attaches the LAN control. Until this is called the menu offers no way to
  /// turn the listener on.
  func attachLANController(_ controller: BridgeLANController) {
    lanController = controller
  }

  /// Toggles LAN access.
  ///
  /// Enablement is never persisted: every launch starts disabled, because a
  /// bridge that silently re-enables itself after a restart is a listener the
  /// user did not ask for this time.
  func toggleLANAccess() {
    guard let lanController, lanTask == nil else { return }
    let shouldEnable: Bool
    switch metrics.lanState {
    case .disabled, .failed: shouldEnable = true
    case .enabled: shouldEnable = false
    case .enabling, .disabling: return
    }
    lanTask = Task { [weak self] in
      if shouldEnable {
        _ = try? await lanController.enable()
      } else {
        try? await lanController.disable()
      }
      let state = await lanController.currentState()
      let advertising = await lanController.isAdvertising()
      await self?.applyLANState(state, isAdvertising: advertising)
    }
  }

  private func applyLANState(_ state: BridgeLANState, isAdvertising: Bool) {
    metrics = BridgeConnectionMetrics(
      lanState: state,
      isAdvertising: isAdvertising,
      activeConnections: metrics.activeConnections,
      unauthenticatedConnections: metrics.unauthenticatedConnections,
      pairedDevices: metrics.pairedDevices,
      observingDevices: metrics.observingDevices,
      deliveredChanges: metrics.deliveredChanges,
      retentionGaps: metrics.retentionGaps
    )
    lanTask = nil
  }

  func attach(_ assembly: CodexBridgeAssembly) {
    self.assembly = assembly
    observationTask = Task { [weak self] in
      for await update in assembly.updates {
        await self?.apply(update)
      }
    }
  }

  func markUnavailable() {
    statusText = "Codex unavailable"
    symbolName = "exclamationmark.circle"
  }

  func detach() {
    observationTask?.cancel()
    observationTask = nil
    lanTask?.cancel()
    lanTask = nil
    assembly = nil
  }

  private func apply(_ update: BridgeUpdate) async {
    switch update {
    case .recovery(let event):
      applyRecovery(event)
    case .stateChanged:
      guard let assembly else { return }
      let snapshot = await assembly.snapshot()
      threadCount = snapshot.threads.count
      pendingApprovalCount = snapshot.pendingApprovals.count
    }
  }

  private func applyRecovery(_ event: CodexRecoveryEvent) {
    switch event {
    case .runtimeState(.stopped):
      statusText = "Paused"
      symbolName = "pause.circle"
    case .runtimeState(.checkingCompatibility), .runtimeState(.starting):
      statusText = "Starting…"
      symbolName = "circle.dotted"
    case .runtimeState(.ready):
      statusText = "Connected"
      symbolName = "checkmark.circle"
    case .runtimeState(.unsupported):
      statusText = "Codex update not yet supported"
      symbolName = "exclamationmark.circle"
    case .runtimeState(.degraded):
      statusText = "Reconnecting…"
      symbolName = "arrow.clockwise.circle"
    case .recoveryStarted, .recoveryFailed:
      statusText = "Reconnecting…"
      symbolName = "arrow.clockwise.circle"
    case .rebuilt:
      break
    }
  }
}
