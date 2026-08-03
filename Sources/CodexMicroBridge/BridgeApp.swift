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
    if let line = model.networkUnavailableLine {
      Text(line)
    }
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
    // Pairing needs a bound listener: the QR carries the endpoint and the
    // served SPKI, and neither exists until LAN is on. Offering the control
    // before then would produce a code pointing at nothing.
    Button("Pair a Device…") {
      model.openPairingWindow()
    }
    .disabled(!model.canPair)
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
    // Menu-bar only is the product decision (Step 2.13): no Dock icon, no
    // main window. On a notched Mac a full menu bar silently drops overflow
    // items, which makes an accessory app unreachable rather than merely
    // inconspicuous — so the acceptance run can opt into a Dock icon. It is
    // an env-gated affordance, not a change to the default: unset, the app
    // behaves exactly as before.
    let wantsDockIcon = ProcessInfo.processInfo.environment["CODEX_MICRO_SHOW_DOCK"] == "1"
    NSApp.setActivationPolicy(wantsDockIcon ? .regular : .accessory)
    if wantsDockIcon {
      NSApp.activate(ignoringOtherApps: true)
    }

    // The Codex runtime and the network graph are built independently, and
    // that separation is the point. An earlier version returned early when the
    // runtime failed, which left LAN and pairing permanently disabled for a
    // reason that has nothing to do with either: the listener already refuses
    // to bind when Codex is unsupported, through its own prerequisite probe.
    // Coupling the whole composition to the runtime attaching meant one
    // failure disabled three unrelated things.
    // Startup outcomes go to unified logging as well as the menu.
    //
    // A menu line can only be read by someone standing at the machine with a
    // screenshot, which is exactly the wrong tool for diagnosing why a bridge
    // will not come up. The code written here is the same closed vocabulary
    // the menu shows, so this adds a channel, not a disclosure.
    let log = OSLogSink()
    func record(_ code: String, level: BridgeLogLevel) {
      log.write(RedactedLogEntry(timestamp: Date(), level: level, code: code, counts: [:]))
      // Also to standard error. Unified logging is the right channel for a
      // shipped app, but it is awkward to read from a terminal and drops
      // info-level entries unless they are explicitly enabled — which makes
      // it useless for the one case that matters most, a bridge that will not
      // start. The code is the same closed vocabulary either way.
      FileHandle.standardError.write(Data("codex-micro: \(code)\n".utf8))
    }

    let assembly: CodexBridgeAssembly?
    do {
      assembly = try CodexBridgeAssembly.live()
      record("startup.runtime.ready", level: .info)
    } catch {
      assembly = nil
      let reason = BridgeStartupReason.describe(error)
      record("startup.runtime.failed.\(reason)", level: .error)
      Task { @MainActor in
        model.markUnavailable(reason: reason)
      }
    }
    self.assembly = assembly

    Task { @MainActor in
      if let assembly {
        model.attach(assembly)
      }
      // News up the network graph and hands the menu its LAN control and
      // pairing service. Until Step 2.14 nothing called this, so the LAN
      // button was permanently greyed out and there was no way to pair at all.
      do {
        let live = try BridgeLiveComposition.make(
          codexProbe: BridgeCodexSupportProbe(
            probe: SystemCodexCompatibilityProbe(
              codexExecutableURL: try CodexExecutableLocator.locate()),
            policy: .phase1
          )
        )
        model.attachLive(live)
        record("startup.network.ready", level: .info)
        // The acceptance path runs only when the operator asks for it, and
        // exits when it is done so a run cannot be mistaken for a session.
        if BridgeAcceptanceRun.isRequested {
          Task {
            let passed = await BridgeAcceptanceRun.run(live)
            await MainActor.run { NSApp.reply(toApplicationShouldTerminate: true) }
            exit(passed ? 0 : 1)
          }
        }
      } catch {
        // A bridge that cannot build its network graph still runs as a local
        // status menu; it simply offers no LAN and no pairing. The reason is
        // shown, because "unavailable" with no cause is undiagnosable.
        let reason = BridgeStartupReason.describe(error)
        record("startup.network.failed.\(reason)", level: .error)
        model.markNetworkUnavailable(reason: reason)
      }
    }

    if let assembly {
      Task { await assembly.start() }
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
