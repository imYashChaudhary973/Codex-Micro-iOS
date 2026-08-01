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

  private var assembly: CodexBridgeAssembly?
  private var observationTask: Task<Void, Never>?

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
