import CompanionProtocol
import Foundation
import XCTest

/// Agent-key binding.
///
/// One rule dominates: a binding never moves on its own. The device's value is
/// that you reach for key 3 without looking, and every convenience that would
/// reorder keys — putting the busiest agent first, compacting away a finished
/// thread — destroys that exactly when you are too busy to notice.
///
/// Most of these tests are therefore about changes that must *not* happen.
final class AgentKeyBindingTests: XCTestCase {

  // MARK: - Stability

  /// The central rule. New activity fills empty slots and touches nothing else.
  func testFillingNeverMovesAnExistingBinding() throws {
    let bindings = AgentKeyBindings.empty
      .binding(threadID: "alpha", to: 0)
      .binding(threadID: "beta", to: 4)

    let filled = bindings.filling(from: [
      try thread(id: "gamma", status: .active, activeTurn: "t"),
      try thread(id: "alpha", status: .idle, lastTurnStatus: .completed),
      try thread(id: "beta", status: .idle, lastTurnStatus: .completed),
    ])

    XCTAssertEqual(filled.threadID(at: 0), "alpha", "an established binding moved")
    XCTAssertEqual(filled.threadID(at: 4), "beta", "an established binding moved")
    XCTAssertEqual(filled.threadID(at: 1), "gamma")
  }

  /// A finished thread keeps its key. Compacting it away would be tidy and
  /// would mean the key you reach for is no longer the agent you meant.
  func testAFinishedThreadKeepsItsSlot() throws {
    let bindings = AgentKeyBindings.empty.binding(threadID: "done", to: 2)

    let filled = bindings.filling(from: [
      try thread(id: "done", status: .idle, lastTurnStatus: .completed),
      try thread(id: "busy", status: .active, activeTurn: "t"),
    ])

    XCTAssertEqual(filled.threadID(at: 2), "done")
    XCTAssertEqual(filled.slot(of: "busy"), 0)
  }

  /// A thread the device can no longer see keeps its slot too. The slot is
  /// spoken for until the user releases it; silently reusing it would hand the
  /// key to a different agent without asking.
  func testAVanishedThreadKeepsItsSlot() throws {
    let bindings = AgentKeyBindings.empty.binding(threadID: "gone", to: 1)

    let filled = bindings.filling(from: [try thread(id: "new", status: .active, activeTurn: "t")])

    XCTAssertEqual(filled.threadID(at: 1), "gone")
    XCTAssertEqual(filled.slot(of: "new"), 0)
  }

  /// Reconciling repeatedly must converge, or the keys rearrange under the
  /// user on every delivery.
  func testFillingIsIdempotent() throws {
    let threads = [
      try thread(id: "a", status: .active, activeTurn: "t"),
      try thread(id: "b", status: .idle, lastTurnStatus: .interrupted),
      try thread(id: "c", status: .idle, lastTurnStatus: .completed),
    ]

    let once = AgentKeyBindings.empty.filling(from: threads)
    let twice = once.filling(from: threads)
    let thrice = twice.filling(from: threads)

    XCTAssertEqual(once, twice)
    XCTAssertEqual(twice, thrice)
  }

  // MARK: - Which threads win a free slot

  /// An agent blocked on you is the reason to look at the device; a finished
  /// one is the reason not to.
  func testWaitingAgentsTakeFreeSlotsBeforeFinishedOnes() throws {
    let filled = AgentKeyBindings.empty.filling(from: [
      try thread(id: "finished", status: .idle, lastTurnStatus: .completed),
      try thread(id: "working", status: .active, activeTurn: "t"),
      try thread(id: "waiting", status: .idle, lastTurnStatus: .interrupted),
    ])

    XCTAssertEqual(filled.threadID(at: 0), "waiting")
    XCTAssertEqual(filled.threadID(at: 1), "working")
    XCTAssertEqual(filled.threadID(at: 2), "finished")
  }

  func testOnlySixThreadsGetKeysAndTheRestAreSimplyUnbound() throws {
    let many = try (0..<10).map {
      try thread(id: "thread-\($0)", status: .active, activeTurn: "t")
    }

    let filled = AgentKeyBindings.empty.filling(from: many)

    XCTAssertEqual(filled.slots.compactMap { $0 }.count, 6)
    XCTAssertNil(filled.slot(of: "thread-9"))
  }

  // MARK: - Explicit changes

  /// The user moving a thread is the only circumstance under which a binding
  /// moves, and it must not leave the thread in two places.
  func testRebindingAThreadClearsItsOldSlot() {
    let bindings = AgentKeyBindings.empty
      .binding(threadID: "alpha", to: 0)
      .binding(threadID: "alpha", to: 3)

    XCTAssertNil(bindings.threadID(at: 0))
    XCTAssertEqual(bindings.threadID(at: 3), "alpha")
    XCTAssertEqual(bindings.boundThreadIDs, ["alpha"])
  }

  func testReleasingASlotFreesItForFilling() throws {
    let bindings = AgentKeyBindings.empty.binding(threadID: "old", to: 0).releasing(slot: 0)

    XCTAssertNil(bindings.threadID(at: 0))
    let filled = bindings.filling(from: [try thread(id: "new", status: .active, activeTurn: "t")])
    XCTAssertEqual(filled.threadID(at: 0), "new")
  }

  // MARK: - Restoring from storage

  /// Two keys pointing at one thread means two keys light identically, and one
  /// of them is a lie about how many agents you have.
  func testRestoringClearsDuplicateBindings() {
    let bindings = AgentKeyBindings(slots: ["a", "b", "a", nil, "b", nil])

    XCTAssertEqual(bindings.threadID(at: 0), "a")
    XCTAssertEqual(bindings.threadID(at: 1), "b")
    XCTAssertNil(bindings.threadID(at: 2), "a duplicate survived restore")
    XCTAssertNil(bindings.threadID(at: 4), "a duplicate survived restore")
  }

  func testRestoringNormalisesLengthInBothDirections() {
    XCTAssertEqual(AgentKeyBindings(slots: []).slots.count, 6)
    XCTAssertEqual(AgentKeyBindings(slots: Array(repeating: "x", count: 20)).slots.count, 6)
    XCTAssertEqual(AgentKeyBindings(slots: ["a"]).threadID(at: 0), "a")
  }

  func testRestoringDropsEmptyIdentifiers() {
    XCTAssertNil(AgentKeyBindings(slots: [""]).threadID(at: 0))
  }

  /// Bindings survive a reconnect, which is the whole reason they are stored.
  func testBindingsRoundTripThroughCoding() throws {
    let bindings = AgentKeyBindings.empty
      .binding(threadID: "alpha", to: 1)
      .binding(threadID: "beta", to: 5)

    let decoded = try JSONDecoder().decode(
      AgentKeyBindings.self, from: try JSONEncoder().encode(bindings))

    XCTAssertEqual(decoded, bindings)
  }

  // MARK: - Helper

  private func thread(
    id: String,
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
