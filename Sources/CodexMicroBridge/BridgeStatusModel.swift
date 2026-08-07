import AppKit
import CompanionCrypto
import CompanionProtocol
import Foundation
import MacBridgeCore
import MacBridgeServer
import Observation
import SwiftUI

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
  private var live: BridgeLiveComposition?
  private var pairingWindow: NSWindow?
  /// The endpoint the listener bound, kept so pairing can name it in the QR.
  private var boundEndpoint: ListenerEndpoint?
  private(set) var networkAvailable = true

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

  /// Attaches the whole production network graph.
  func attachLive(_ composition: BridgeLiveComposition) {
    live = composition
    lanController = composition.lanController
  }

  /// The bridge runs as a local status menu but offers no LAN or pairing.
  func markNetworkUnavailable(reason: String = "unknown") {
    networkAvailable = false
    networkFailureReason = reason
    lanController = nil
  }

  /// Why the network graph could not be built, for the menu.
  private(set) var networkFailureReason: String?

  /// One line describing LAN availability, or nil when it is available.
  var networkUnavailableLine: String? {
    guard !networkAvailable else { return nil }
    return "LAN unavailable: \(networkFailureReason ?? "unknown")"
  }

  /// Pairing needs a bound listener, because the QR carries the endpoint and
  /// the SPKI the listener is actually serving.
  var canPair: Bool {
    guard live != nil, boundEndpoint != nil else { return false }
    if case .enabled = metrics.lanState { return true }
    return false
  }

  /// Whether the Mac can grant a project to a paired device.
  ///
  /// Independent of LAN being up: grants are Keychain state. Still requires
  /// the live composition so the registry and authority exist.
  var canGrantProject: Bool {
    live != nil && !isGrantingProject
  }

  /// In-flight grant so the menu does not double-fire the folder picker.
  private(set) var isGrantingProject = false

  /// Last admin result for the menu (counts only; no paths or IDs).
  private(set) var lastAdminSummary: String?

  /// Opens a folder picker and grants that project to every live paired device.
  ///
  /// This is the step pairing deliberately leaves out: without it a phone
  /// authenticates, sees zero threads, and every key is refused.
  func grantProjectToPairedDevices() {
    guard let live, !isGrantingProject else { return }
    isGrantingProject = true
    lastAdminSummary = nil
    Task { [weak self] in
      defer {
        Task { @MainActor in self?.isGrantingProject = false }
      }
      do {
        let outcomes = try await BridgeDeviceAdministration.grantSelectedFolderToAllDevices(
          live: live)
        let devices = outcomes.count
        let attributed = outcomes.map(\.attributedThreadCount).reduce(0, +)
        let adopted = outcomes.map(\.adoptedThreadCount).reduce(0, +)
        await MainActor.run {
          self?.lastAdminSummary =
            "Granted to \(devices) device(s); adopted \(adopted) thread(s), "
            + "attributed \(attributed)"
          self?.metrics = BridgeConnectionMetrics(
            lanState: self?.metrics.lanState ?? .disabled,
            isAdvertising: self?.metrics.isAdvertising ?? false,
            activeConnections: self?.metrics.activeConnections ?? 0,
            unauthenticatedConnections: self?.metrics.unauthenticatedConnections ?? 0,
            pairedDevices: max(self?.metrics.pairedDevices ?? 0, devices),
            observingDevices: self?.metrics.observingDevices ?? 0,
            deliveredChanges: self?.metrics.deliveredChanges ?? 0,
            retentionGaps: self?.metrics.retentionGaps ?? 0
          )
        }
      } catch BridgeDeviceAdministration.Failure.noPairedDevice {
        await MainActor.run { self?.lastAdminSummary = "No paired device yet — pair first" }
      } catch BridgeDeviceAdministration.Failure.projectUnresolved {
        await MainActor.run { self?.lastAdminSummary = "No folder selected" }
      } catch {
        await MainActor.run { self?.lastAdminSummary = "Grant failed" }
      }
    }
  }

  /// Opens the pairing window and starts a session.
  func openPairingWindow() {
    guard let live, let endpoint = boundEndpoint else { return }
    presentPairingWindow(live)
    Task {
      do {
        try await live.pairing.beginPairing(
          endpoint: endpoint,
          selection: try SecureProtocolSelection(
            major: 1, minor: 1, features: [.observeSync])
        )
      } catch {
        await MainActor.run { live.pairingModel.set(.failed(reason: "sessionUnavailable")) }
      }
    }
  }

  private func presentPairingWindow(_ live: BridgeLiveComposition) {
    if let pairingWindow {
      pairingWindow.makeKeyAndOrderFront(nil)
      NSApp.activate(ignoringOtherApps: true)
      return
    }
    let view = BridgePairingView(
      model: live.pairingModel,
      onBegin: { [weak self] in self?.openPairingWindow() },
      onConfirm: { Task { await live.pairing.confirmDisplayedPhrase() } },
      onCancel: { [weak self] in
        Task { await live.pairing.cancel() }
        self?.closePairingWindow()
      }
    )
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 380, height: 460),
      styleMask: [.titled, .closable],
      backing: .buffered,
      defer: false
    )
    window.title = "Pair a Device"
    window.contentView = NSHostingView(rootView: view)
    window.center()
    window.isReleasedWhenClosed = false
    pairingWindow = window
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  private func closePairingWindow() {
    pairingWindow?.orderOut(nil)
    pairingWindow = nil
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
      var endpoint: ListenerEndpoint?
      if shouldEnable {
        endpoint = try? await lanController.enable()
      } else {
        try? await lanController.disable()
      }
      await MainActor.run { self?.boundEndpoint = endpoint }
      let state = await lanController.currentState()
      let advertising = await lanController.isAdvertising()
      await self?.applyLANState(state, isAdvertising: advertising)
    }
  }

  /// Reports the LAN outcome on the same diagnostic channel as startup.
  ///
  /// Enabling LAN is the step most likely to fail for an environmental reason
  /// — a refused local-network permission, no eligible interface, a Bonjour
  /// publication the system declines — and all of those look identical in the
  /// menu unless the closed reason is written somewhere readable.
  private func reportLAN(_ state: BridgeLANState, isAdvertising: Bool) {
    let code: String
    switch state {
    case .disabled: code = "lan.disabled"
    case .enabling: code = "lan.enabling"
    case .enabled: code = "lan.enabled.advertising=\(isAdvertising)"
    case .disabling: code = "lan.disabling"
    case .failed(let reason): code = "lan.failed.\(reason.rawValue)"
    }
    OSLogSink().write(
      RedactedLogEntry(timestamp: Date(), level: .info, code: code, counts: [:]))
    FileHandle.standardError.write(Data("codex-micro: \(code)\n".utf8))
  }

  private func applyLANState(_ state: BridgeLANState, isAdvertising: Bool) {
    reportLAN(state, isAdvertising: isAdvertising)
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

  func markUnavailable(reason: String = "unknown") {
    statusText = "Codex unavailable (\(reason))"
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
