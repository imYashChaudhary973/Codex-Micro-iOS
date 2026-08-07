import AppKit
import CompanionProtocol
import Foundation
import MacBridgeCore

/// Mac-side grant and project administration for paired devices.
///
/// Pairing deliberately leaves a device at `{view}` with an empty project
/// allowlist (plan §2 invariant 4). That is correct as a default and useless
/// as an end state: every key stays dark and every command is refused. This
/// type is the production path that raises a grant to a working scope —
/// the same work the acceptance run did only under env flags.
///
/// Nothing here is automatic. A folder is registered and a device is widened
/// only because the Mac user chose them.
enum BridgeDeviceAdministration {
  /// Capabilities a working pad needs without opening the highest-privilege
  /// surfaces.
  ///
  /// `.approve` stays off until the Mac surfaces pending approvals. Granting
  /// it without a delivery path makes accept/reject keys look available and
  /// then fail — the shape invariant 2 exists to prevent.
  static let workingCapabilities: Set<DeviceCapability> = [
    .view, .interrupt, .runAgent, .startThread,
  ]

  /// Result of granting one folder to one device.
  struct GrantOutcome: Equatable, Sendable {
    let deviceID: UUID
    let projectID: String
    let rootPath: String
    let alreadyScoped: Bool
    let attributedThreadCount: Int
    let adoptedThreadCount: Int
  }

  /// Closed failure vocabulary for the menu.
  enum Failure: Error, Equatable, Sendable {
    case noPairedDevice
    case projectUnresolved
    case grantFailed
    case authorityUnavailable
  }

  /// Registers `rootPath`, grants working capabilities and project scope to
  /// `deviceID`, attributes known threads, and discovers recent Codex work.
  static func grantProject(
    rootPath: String,
    deviceID: UUID,
    live: BridgeLiveComposition
  ) async throws -> GrantOutcome {
    guard let project = await live.registry.register(rootPath: rootPath) else {
      report("admin.projectUnresolved")
      throw Failure.projectUnresolved
    }

    await live.workspaceRoots.update(projects: live.registry.allProjects())

    do {
      _ = try await live.authority.amendCapabilities(
        deviceID: deviceID,
        capabilities: workingCapabilities,
        actionProfileCeiling: .runWorkspace
      )
    } catch DeviceGrantAuthorityError.authorityUnavailable {
      report("admin.authorityUnavailable")
      throw Failure.authorityUnavailable
    } catch {
      report("admin.amendFailed")
      throw Failure.grantFailed
    }

    let alreadyScoped: Bool
    do {
      let existing = try await live.authority.authoritativeGrant(deviceID: deviceID)
      if existing.permittedProjectIDs.contains(project.projectID) {
        alreadyScoped = true
        report("admin.alreadyScoped", "project=\(project.projectID.prefix(8))…")
      } else {
        alreadyScoped = false
        // Union, not replacement: widenScope demands a strict superset and
        // replacing would drop every previously granted project.
        let widened = existing.permittedProjectIDs.union([project.projectID])
        _ = try await live.authority.widenScope(
          deviceID: deviceID, permittedProjectIDs: widened)
        report(
          "admin.widened",
          "projects=\(widened.count) added=\(project.projectID.prefix(8))…")
      }
    } catch DeviceGrantAuthorityError.authorityUnavailable {
      report("admin.authorityUnavailable")
      throw Failure.authorityUnavailable
    } catch {
      report("admin.widenFailed")
      throw Failure.grantFailed
    }

    let adopted = await live.codexAssembly?.discoverAndAdoptRecentThreads(limit: 24) ?? 0
    let attributed = await attributeKnownThreads(live: live)

    // Pump once so any journal activity from adoption becomes broker events
    // before the next phone subscribe/ack.
    _ = await live.pump?.drain()

    report(
      "admin.granted",
      "adopted=\(adopted) attributed=\(attributed)")

    return GrantOutcome(
      deviceID: deviceID,
      projectID: project.projectID,
      rootPath: project.rootPath,
      alreadyScoped: alreadyScoped,
      attributedThreadCount: attributed,
      adoptedThreadCount: adopted
    )
  }

  /// Grants the user-selected folder to every live (non-tombstoned) device.
  ///
  /// Typical personal setup has one phone. Applying to all live grants keeps
  /// the menu to one action rather than a device picker.
  static func grantSelectedFolderToAllDevices(
    live: BridgeLiveComposition
  ) async throws -> [GrantOutcome] {
    let devices = try await livePairedDeviceIDs(live: live)
    guard !devices.isEmpty else {
      report("admin.noPairedDevice")
      throw Failure.noPairedDevice
    }
    guard let rootPath = await pickFolder() else {
      report("admin.folderCancelled")
      throw Failure.projectUnresolved
    }
    var outcomes: [GrantOutcome] = []
    for deviceID in devices {
      let outcome = try await grantProject(rootPath: rootPath, deviceID: deviceID, live: live)
      outcomes.append(outcome)
    }
    return outcomes
  }

  /// Live paired device IDs (excludes tombstones).
  static func livePairedDeviceIDs(live: BridgeLiveComposition) async throws -> [UUID] {
    let snapshot: GrantAuthorityAdministrationSnapshot
    do {
      snapshot = try await live.authority.macAdministrationSnapshot()
    } catch {
      throw Failure.authorityUnavailable
    }
    return snapshot.grants
      .filter { $0.tombstone == nil }
      .map(\.deviceID)
      .sorted { $0.uuidString < $1.uuidString }
  }

  /// Resolves every thread currently in the bridge snapshot into a registered
  /// project. Unattributable threads stay invisible (fail-closed).
  static func attributeKnownThreads(live: BridgeLiveComposition) async -> Int {
    let runtime = live.runtime
    let resolver = BridgeThreadAttributionResolver(
      registry: live.registry,
      table: live.attribution,
      readThread: { threadID in
        guard let runtime else { throw CodexRuntimeRequestError.notReady }
        return try await runtime.readThread(threadID: threadID, includeTurns: false)
      }
    )

    // Prefer IDs already in the companion snapshot; fall back to re-list if
    // the store is still empty after discovery.
    var threadIDs: [String] = []
    if let assembly = live.codexAssembly {
      let snap = await assembly.snapshot()
      threadIDs = snap.threads.map(\.threadID)
    }
    if threadIDs.isEmpty, let runtime = live.runtime {
      threadIDs = (try? await runtime.listRecentThreadIDs(limit: 24)) ?? []
    }

    var count = 0
    for threadID in threadIDs {
      if await resolver.resolve(threadID: threadID) != nil {
        count += 1
        // Recording a change forces the broker to re-filter for subscribers.
        _ = await live.assembly.broker.recordThreadChange(threadID: threadID)
      }
    }
    return count
  }

  // MARK: - UI

  @MainActor
  private static func pickFolder() async -> String? {
    let panel = NSOpenPanel()
    panel.canChooseFiles = false
    panel.canChooseDirectories = true
    panel.allowsMultipleSelection = false
    panel.prompt = "Grant Project"
    panel.message = "Choose a folder this phone may observe and control in Codex."
    panel.directoryURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let response = panel.runModal()
    guard response == .OK, let url = panel.url else { return nil }
    return url.path
  }

  private static func report(_ code: String, _ detail: String = "") {
    let line = detail.isEmpty ? "codex-micro: \(code)" : "codex-micro: \(code) — \(detail)"
    FileHandle.standardError.write(Data((line + "\n").utf8))
  }
}
