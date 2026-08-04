import CompanionProtocol
import Foundation
import XCTest

/// The agent-key surface.
///
/// Phase 3 invariant 1: a key never lies about state. Most of these tests are
/// about the ways a status display lies — holding a colour after the feed
/// stops, pulsing for an agent that already finished, quietly emptying a slot
/// whose thread went out of scope — rather than about the happy path.
final class DeviceSurfaceTests: XCTestCase {

  // MARK: - Activity derivation

  func testARunningTurnReadsAsWorking() throws {
    let state = AgentKeyActivity.derive(
      from: try thread(status: .active, activeTurn: "turn-1", lastTurnStatus: .inProgress))

    XCTAssertEqual(state, .working)
  }

  /// A thread can be `active` while its turn has already finished. Pulsing for
  /// an agent that is done is exactly the lie the invariant forbids.
  func testAnActiveThreadWithNoRunningTurnDoesNotReadAsWorking() throws {
    let state = AgentKeyActivity.derive(
      from: try thread(status: .active, activeTurn: nil, lastTurnStatus: .completed))

    XCTAssertEqual(state, .finished)
  }

  /// Error beats everything. A failed thread must not read as finished merely
  /// because some earlier turn completed.
  func testAThreadInErrorReadsAsFailedWhateverItsLastTurnDid() throws {
    for last in [CompanionTurnStatus.completed, .inProgress, .interrupted, .unknown] {
      let state = AgentKeyActivity.derive(
        from: try thread(status: .error, activeTurn: "turn-1", lastTurnStatus: last))
      XCTAssertEqual(state, .failed, "last turn \(last)")
    }
  }

  /// An in-flight turn that has already failed must not pulse.
  func testAnActiveButFailedTurnReadsAsFailed() throws {
    let state = AgentKeyActivity.derive(
      from: try thread(status: .active, activeTurn: "turn-1", lastTurnStatus: .failed))

    XCTAssertEqual(state, .failed)
  }

  /// Interrupted means the agent stopped and wants direction — the hardware's
  /// waiting colour, not its finished one.
  func testAnInterruptedTurnReadsAsWaiting() throws {
    let state = AgentKeyActivity.derive(
      from: try thread(status: .idle, activeTurn: nil, lastTurnStatus: .interrupted))

    XCTAssertEqual(state, .waiting)
  }

  /// "In progress" with no active turn is a contradiction between the Mac's
  /// view and ours. Unknown is the honest answer; picking a side would be a
  /// guess rendered as fact.
  func testAContradictoryStateReadsAsUnknownRatherThanGuessing() throws {
    let state = AgentKeyActivity.derive(
      from: try thread(status: .active, activeTurn: nil, lastTurnStatus: .inProgress))

    XCTAssertEqual(state, .unknown)
  }

  // MARK: - Freshness

  /// The central invariant. A feed that stops must not leave keys claiming to
  /// be current.
  func testKeysGoStaleWhenTheFeedStops() throws {
    let projection = DeviceSurfaceProjection(freshnessBudget: 10)
    let now = Date(timeIntervalSince1970: 1_000_000)
    let observed = [try thread(id: "t1", status: .active, activeTurn: "turn-1")]

    let live = projection.project(
      bindings: ["t1"], threads: observed, lastUpdate: now.addingTimeInterval(-5),
      now: now, isConnected: true)
    let stale = projection.project(
      bindings: ["t1"], threads: observed, lastUpdate: now.addingTimeInterval(-30),
      now: now, isConnected: true)

    XCTAssertEqual(live.agentKeys[0].freshness, .live)
    XCTAssertEqual(stale.agentKeys[0].freshness, .stale)
    // The activity is retained: "it was running when we last heard" beats
    // blank, as long as the key also says it is unsure.
    XCTAssertEqual(stale.agentKeys[0].activity, .working)
  }

  /// Having never heard anything is not the same as being current.
  func testNeverHavingHeardAnythingIsStaleNotLive() throws {
    let projection = DeviceSurfaceProjection()

    let surface = projection.project(
      bindings: ["t1"], threads: [], lastUpdate: nil,
      now: Date(timeIntervalSince1970: 1_000_000), isConnected: true)

    XCTAssertEqual(surface.agentKeys[0].freshness, .stale)
  }

  func testDisconnectedDarkensEveryKeyRegardlessOfWhatWasKnown() throws {
    let projection = DeviceSurfaceProjection()
    let now = Date(timeIntervalSince1970: 1_000_000)

    let surface = projection.project(
      bindings: ["t1", "t2"],
      threads: [try thread(id: "t1", status: .active, activeTurn: "turn-1")],
      lastUpdate: now, now: now, isConnected: false)

    XCTAssertFalse(surface.isConnected)
    XCTAssertEqual(surface.agentKeys.count, 6)
    for key in surface.agentKeys {
      XCTAssertEqual(key.freshness, .disconnected)
      XCTAssertFalse(key.isActionable, "a disconnected key offered an action")
    }
  }

  // MARK: - Bindings

  func testTheSurfaceAlwaysHasExactlySixKeys() throws {
    let projection = DeviceSurfaceProjection()
    let now = Date(timeIntervalSince1970: 1_000_000)

    for bindings in [[], ["a"], Array(repeating: "x", count: 12)] {
      let surface = projection.project(
        bindings: bindings.map { Optional($0) }, threads: [], lastUpdate: now,
        now: now, isConnected: true)
      XCTAssertEqual(surface.agentKeys.count, 6, "bindings count \(bindings.count)")
      XCTAssertEqual(surface.agentKeys.map(\.slot), Array(0..<6))
    }
  }

  /// A slot bound to a thread the device can no longer see stays bound and
  /// reads unknown. Silently emptying it would hide a revocation behind what
  /// looks like an unused key.
  func testABindingToAnUnseenThreadStaysBoundAndReadsUnknown() throws {
    let projection = DeviceSurfaceProjection()
    let now = Date(timeIntervalSince1970: 1_000_000)

    let surface = projection.project(
      bindings: ["vanished"], threads: [], lastUpdate: now, now: now, isConnected: true)

    XCTAssertTrue(surface.agentKeys[0].isBound)
    XCTAssertEqual(surface.agentKeys[0].threadID, "vanished")
    XCTAssertEqual(surface.agentKeys[0].activity, .unknown)
    XCTAssertNil(surface.agentKeys[0].projectID)
  }

  func testAnUnboundSlotIsDarkButNotDisconnected() {
    let key = AgentKeyState.unbound(slot: 3)

    XCTAssertFalse(key.isBound)
    XCTAssertFalse(key.isActionable)
    XCTAssertEqual(key.freshness, .live)
  }

  // MARK: - Selection

  func testSelectingAnUnboundSlotSelectsNothing() throws {
    let projection = DeviceSurfaceProjection()
    let now = Date(timeIntervalSince1970: 1_000_000)

    let surface = projection.project(
      bindings: [nil], threads: [], lastUpdate: now, now: now,
      isConnected: true, selectedSlot: 0)

    XCTAssertNil(surface.selectedSlot)
    XCTAssertNil(surface.selectedKey)
  }

  func testSelectingABoundSlotResolvesToThatKey() throws {
    let projection = DeviceSurfaceProjection()
    let now = Date(timeIntervalSince1970: 1_000_000)

    let surface = projection.project(
      bindings: [nil, "t2"],
      threads: [try thread(id: "t2", status: .idle, lastTurnStatus: .completed)],
      lastUpdate: now, now: now, isConnected: true, selectedSlot: 1)

    XCTAssertEqual(surface.selectedSlot, 1)
    XCTAssertEqual(surface.selectedKey?.threadID, "t2")
    XCTAssertEqual(surface.selectedKey?.activity, .finished)
  }

  func testAnOutOfRangeSelectionIsIgnored() throws {
    let projection = DeviceSurfaceProjection()
    let now = Date(timeIntervalSince1970: 1_000_000)

    let surface = projection.project(
      bindings: ["t1"], threads: [], lastUpdate: now, now: now,
      isConnected: true, selectedSlot: 99)

    XCTAssertNil(surface.selectedSlot)
  }

  // MARK: - Helper

  private func thread(
    id: String = "thread-1",
    status: CompanionThreadStatus,
    activeTurn: String? = nil,
    lastTurnStatus: CompanionTurnStatus? = nil
  ) throws -> ObservedThreadState {
    try ObservedThreadState(
      threadID: id,
      projectID: "project-a",
      status: status,
      activeTurnID: activeTurn,
      lastTurnID: lastTurnStatus == nil ? nil : "turn-last",
      lastTurnStatus: lastTurnStatus
    )
  }
}
