import CompanionProtocol
import Foundation
import XCTest

/// Command-key availability.
///
/// Invariant 2: a control a device may not use is visibly unavailable rather
/// than present-and-failing. A key that looks alive and refuses is
/// indistinguishable from one that looks alive and is broken, so the user
/// learns to distrust all of them.
final class CommandKeyTests: XCTestCase {

  // MARK: - Capability

  func testStopNeedsInterruptAndSteerNeedsRunAgent() throws {
    let surface = try workingSurface()

    XCTAssertEqual(
      CommandKey.stop.availability(in: surface, capabilities: [.view]), .notPermitted)
    XCTAssertEqual(
      CommandKey.stop.availability(in: surface, capabilities: [.view, .interrupt]), .available)
    XCTAssertEqual(
      CommandKey.steer.availability(in: surface, capabilities: [.view, .interrupt]),
      .notPermitted)
    XCTAssertEqual(
      CommandKey.steer.availability(in: surface, capabilities: [.runAgent]), .available)
  }

  /// Navigation changes what the phone is looking at and causes nothing to
  /// happen on the Mac, so it survives a grant reduced to nothing.
  func testNavigationKeysStayUsableWithNoCapabilitiesAtAll() throws {
    let surface = try workingSurface()

    for key in [CommandKey.previousAgent, .nextAgent] {
      XCTAssertEqual(key.availability(in: surface, capabilities: []), .available, key.rawValue)
      XCTAssertNil(key.requiredCapability)
    }
  }

  // MARK: - Selection and liveness

  func testActingKeysNeedASelection() throws {
    let surface = try surface(selected: nil)

    for key in CommandKey.allCases where key.requiresSelection {
      XCTAssertEqual(
        key.availability(in: surface, capabilities: Set(DeviceCapability.allCases)),
        .noSelection, key.rawValue)
    }
  }

  /// A stale key's activity is a memory, not a fact. Acting on it would be
  /// acting on a guess — the same lie invariant 1 forbids, one step later.
  func testAStaleAgentCannotBeActedOn() throws {
    let surface = try workingSurface(freshness: .stale)

    XCTAssertEqual(
      CommandKey.stop.availability(in: surface, capabilities: [.interrupt]), .notLive)
  }

  func testDisconnectedDisablesEveryKeyIncludingNavigation() {
    for key in CommandKey.allCases {
      XCTAssertEqual(
        key.availability(
          in: .disconnected, capabilities: Set(DeviceCapability.allCases)),
        .notLive, key.rawValue)
    }
  }

  // MARK: - Running turn

  /// Stopping a finished agent and steering one that is not thinking are
  /// no-ops the gateway would refuse. Saying so before the tap is the same
  /// information, delivered earlier.
  func testStopAndSteerNeedARunningTurn() throws {
    let finished = try surface(activity: .finished)

    XCTAssertEqual(
      CommandKey.stop.availability(in: finished, capabilities: [.interrupt]), .noRunningTurn)
    XCTAssertEqual(
      CommandKey.steer.availability(in: finished, capabilities: [.runAgent]), .noRunningTurn)
  }

  /// Marking read is about what you have seen, not about what the agent is
  /// doing, so a finished thread can still be marked.
  func testMarkReadDoesNotNeedARunningTurn() throws {
    let finished = try surface(activity: .finished)

    XCTAssertEqual(
      CommandKey.markRead.availability(in: finished, capabilities: [.view]), .available)
  }

  // MARK: - Ordering of reasons

  /// A disconnected device reporting a permission problem would send someone
  /// to change a grant that was never the issue.
  func testConnectionOutranksPermission() {
    XCTAssertEqual(
      CommandKey.stop.availability(in: .disconnected, capabilities: []), .notLive)
  }

  func testSelectionOutranksPermission() throws {
    let surface = try surface(selected: nil)

    XCTAssertEqual(
      CommandKey.stop.availability(in: surface, capabilities: []), .noSelection)
  }

  // MARK: - Helpers

  private func workingSurface(
    freshness: AgentKeyFreshness = .live
  ) throws -> DeviceSurfaceState {
    try surface(activity: .working, freshness: freshness)
  }

  private func surface(
    activity: AgentKeyActivity = .working,
    freshness: AgentKeyFreshness = .live,
    selected: Int? = 0
  ) throws -> DeviceSurfaceState {
    let key = AgentKeyState(
      slot: 0, threadID: "thread-a", projectID: "project-a",
      activity: activity, freshness: freshness)
    var keys = [key]
    keys.append(contentsOf: (1..<AgentKeyState.slotCount).map { AgentKeyState.unbound(slot: $0) })
    return DeviceSurfaceState(agentKeys: keys, selectedSlot: selected, isConnected: true)
  }
}
