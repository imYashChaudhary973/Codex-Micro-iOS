import CompanionProtocol
import Foundation
import Testing

@testable import CodexMicroBridge

/// Grant administration is the production path that turns a paired-but-blind
/// device into one that can see sessions and run commands.
@Suite struct BridgeDeviceAdministrationTests {
  @Test func workingCapabilitiesExcludeApprove() {
    #expect(!BridgeDeviceAdministration.workingCapabilities.contains(.approve))
    #expect(BridgeDeviceAdministration.workingCapabilities.contains(.view))
    #expect(BridgeDeviceAdministration.workingCapabilities.contains(.interrupt))
    #expect(BridgeDeviceAdministration.workingCapabilities.contains(.runAgent))
    #expect(BridgeDeviceAdministration.workingCapabilities.contains(.startThread))
  }

  @Test func projectRegistryAcceptsAbsoluteFolder() async {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-micro-admin-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let registry = BridgeProjectRegistry()
    let project = await registry.register(rootPath: root.path)
    #expect(project != nil)
    #expect(project?.rootPath.hasPrefix("/") == true)

    let again = await registry.register(rootPath: root.path)
    #expect(again?.projectID == project?.projectID)
  }
}
