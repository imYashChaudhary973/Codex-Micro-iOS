import AppKit
import MacBridgeCore
import SwiftUI

/// Development menu-bar shell hosting the bridge assembly: starts the
/// supervised runtime on launch, pauses cleanly for system sleep, resumes on
/// wake, and stops on quit. Signing, notarization, and app-bundle packaging
/// are a later release step; the wiring below is the production lifecycle.
@main
struct CodexMicroBridgeApp: App {
  @NSApplicationDelegateAdaptor(BridgeAppDelegate.self) private var delegate

  var body: some Scene {
    MenuBarExtra("Codex Micro", systemImage: delegate.model.symbolName) {
      BridgeMenu(model: delegate.model)
    }
  }
}

struct BridgeMenu: View {
  let model: BridgeStatusModel

  var body: some View {
    Text(model.statusText)
    Text("Threads: \(model.threadCount)")
    Text("Pending approvals: \(model.pendingApprovalCount)")
    Divider()
    // Redacted connection metrics (plan Step 2.13). Every line is a count or
    // a closed state; `BridgeConnectionMetrics` has no field that could carry
    // an address, name, or identifier.
    ForEach(model.metrics.menuLines, id: \.self) { line in
      Text(line)
    }
    Divider()
    // The LAN control. It is deliberately the only way to turn the listener
    // on, and it is off on every launch: enablement is never remembered,
    // because a bridge that silently re-enables itself after a restart is a
    // listener the user did not ask for this time.
    Button(model.lanButtonTitle) {
      model.toggleLANAccess()
    }
    .disabled(!model.isLANControlEnabled)
    Divider()
    Button("Quit Codex Micro Bridge") {
      NSApp.terminate(nil)
    }
  }
}

final class BridgeAppDelegate: NSObject, NSApplicationDelegate {
  @MainActor let model = BridgeStatusModel()
  private var assembly: CodexBridgeAssembly?

  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.accessory)

    let assembly: CodexBridgeAssembly
    do {
      assembly = try CodexBridgeAssembly.live()
    } catch {
      Task { @MainActor in
        model.markUnavailable()
      }
      return
    }
    self.assembly = assembly
    Task { @MainActor in
      model.attach(assembly)
    }
    Task {
      await assembly.start()
    }

    let workspaceCenter = NSWorkspace.shared.notificationCenter
    workspaceCenter.addObserver(
      self,
      selector: #selector(systemWillSleep),
      name: NSWorkspace.willSleepNotification,
      object: nil
    )
    workspaceCenter.addObserver(
      self,
      selector: #selector(systemDidWake),
      name: NSWorkspace.didWakeNotification,
      object: nil
    )
  }

  func applicationWillTerminate(_ notification: Notification) {
    let assembly = assembly
    self.assembly = nil
    Task {
      await assembly?.stop()
    }
  }

  @objc private func systemWillSleep() {
    let assembly = assembly
    Task {
      await assembly?.suspend()
    }
  }

  @objc private func systemDidWake() {
    let assembly = assembly
    Task {
      await assembly?.resume()
    }
  }
}
