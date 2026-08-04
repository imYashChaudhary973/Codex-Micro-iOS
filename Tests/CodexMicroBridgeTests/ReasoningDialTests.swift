import CompanionProtocol
import Foundation
import XCTest

/// The reasoning dial.
///
/// The dial's hardest job is telling the truth about *when* it takes effect.
/// The physical control is described as turnable mid-task; the app-server
/// surface applies an override from the next turn, because `TurnSteerParams`
/// carries no effort field. A control that silently defers is worse than one
/// that says it will — the user turns it, sees nothing, and concludes it is
/// broken.
final class ReasoningDialTests: XCTestCase {

  // MARK: - Timing

  func testTheDialSaysItAppliesAfterARunningTurn() {
    let dial = ReasoningDialState.resolve(
      positions: ["low", "high"], requested: "high",
      surface: surface(activity: .working), capabilities: [.runAgent])

    XCTAssertEqual(dial.timing, .afterCurrentTurn)
    XCTAssertTrue(dial.timingDescription.lowercased().contains("running"))
  }

  func testTheDialSaysNextTurnWhenNothingIsRunning() {
    let dial = ReasoningDialState.resolve(
      positions: ["low", "high"], requested: "low",
      surface: surface(activity: .finished), capabilities: [.runAgent])

    XCTAssertEqual(dial.timing, .nextTurn)
  }

  // MARK: - Positions

  /// A host that changed models may no longer offer the level the dial points
  /// at. Continuing to show it would be the dial claiming a setting that gets
  /// dropped on send.
  func testASelectionTheHostNoLongerOffersIsCleared() {
    let dial = ReasoningDialState.resolve(
      positions: ["low", "high"], requested: "ludicrous",
      surface: surface(), capabilities: [.runAgent])

    XCTAssertNil(dial.selected)
  }

  func testNoAdvertisedPositionsMakesTheDialUnavailable() {
    let dial = ReasoningDialState.resolve(
      positions: [], requested: nil, surface: surface(), capabilities: [.runAgent])

    XCTAssertEqual(dial.unavailability, .noPositionsOffered)
    XCTAssertFalse(dial.isAvailable)
  }

  /// Positions keep the model's advertised order rather than being sorted,
  /// because "low, medium, high" is a sequence the phone should not invent.
  func testPositionsKeepTheAdvertisedOrder() {
    let dial = ReasoningDialState.resolve(
      positions: ["xhigh", "low", "medium"], requested: nil,
      surface: surface(), capabilities: [.runAgent])

    XCTAssertEqual(dial.positions, ["xhigh", "low", "medium"])
  }

  // MARK: - Travel

  /// A real dial stops rather than wrapping. Wrapping from the highest
  /// setting straight to the lowest is the kind of surprise that costs a long
  /// turn.
  func testTheDialStopsAtBothEndsInsteadOfWrapping() {
    let dial = ReasoningDialState.resolve(
      positions: ["low", "medium", "high"], requested: "high",
      surface: surface(), capabilities: [.runAgent])

    XCTAssertNil(dial.stepped(by: 1), "the dial wrapped past its highest position")
    XCTAssertEqual(dial.stepped(by: -1), "medium")

    let lowest = ReasoningDialState.resolve(
      positions: ["low", "medium", "high"], requested: "low",
      surface: surface(), capabilities: [.runAgent])
    XCTAssertNil(lowest.stepped(by: -1), "the dial wrapped past its lowest position")
  }

  func testSteppingFromNoSelectionEntersAtTheNearEnd() {
    let dial = ReasoningDialState.resolve(
      positions: ["low", "medium", "high"], requested: nil,
      surface: surface(), capabilities: [.runAgent])

    XCTAssertEqual(dial.stepped(by: 1), "low")
    XCTAssertEqual(dial.stepped(by: -1), "high")
  }

  // MARK: - Availability

  /// The dial only affects turns this device could start or steer. Offering it
  /// to a device that can do neither would be a control with no effect.
  func testADeviceThatCannotRunAgentsHasNoDial() {
    let dial = ReasoningDialState.resolve(
      positions: ["low"], requested: nil, surface: surface(),
      capabilities: [.view, .interrupt])

    XCTAssertEqual(dial.unavailability, .notPermitted)
  }

  func testAStaleOrDisconnectedSurfaceDisablesTheDial() {
    let stale = ReasoningDialState.resolve(
      positions: ["low"], requested: nil,
      surface: surface(freshness: .stale), capabilities: [.runAgent])
    let gone = ReasoningDialState.resolve(
      positions: ["low"], requested: nil, surface: .disconnected,
      capabilities: [.runAgent])

    XCTAssertEqual(stale.unavailability, .notLive)
    XCTAssertEqual(gone.unavailability, .notLive)
  }

  func testNoSelectedAgentDisablesTheDial() {
    let dial = ReasoningDialState.resolve(
      positions: ["low"], requested: nil, surface: surface(selected: nil),
      capabilities: [.runAgent])

    XCTAssertEqual(dial.unavailability, .noSelection)
  }

  // MARK: - Helper

  private func surface(
    activity: AgentKeyActivity = .working,
    freshness: AgentKeyFreshness = .live,
    selected: Int? = 0
  ) -> DeviceSurfaceState {
    var keys = [
      AgentKeyState(
        slot: 0, threadID: "thread-a", projectID: "project-a",
        activity: activity, freshness: freshness)
    ]
    keys.append(contentsOf: (1..<AgentKeyState.slotCount).map { AgentKeyState.unbound(slot: $0) })
    return DeviceSurfaceState(agentKeys: keys, selectedSlot: selected, isConnected: true)
  }
}
