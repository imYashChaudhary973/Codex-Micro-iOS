import CompanionProtocol
import Foundation
import XCTest

/// Key remapping.
///
/// The gate for this step is that a remap cannot grant a capability the device
/// lacks. Everything else about remapping is convenience; this is the part
/// that has to hold.
final class KeyRemappingTests: XCTestCase {

  /// Moving an action to a different position must not change what it costs.
  func testAnActionsCapabilityDoesNotDependOnItsPosition() {
    for position in 0..<KeyLayout.positionCount {
      let layout = KeyLayout.default.assigning(.approve, to: position)
      // Whatever else the layout ends up containing, `approve` is unusable
      // wherever it sits. Asserting the whole set would test which action got
      // overwritten, not the property under test.
      XCTAssertTrue(
        layout.unusableActions(given: [.view, .interrupt]).contains(.approve),
        "approve became usable at position \(position)")
    }
  }

  /// Putting `approve` on the most convenient key does not make a device
  /// without `.approve` able to use it.
  func testRemappingCannotGrantACapability() {
    let layout = KeyLayout(actions: [.approve, .approve, .newChat, .steer, .stop, .markRead])

    let unusable = layout.unusableActions(given: [.view])

    XCTAssertEqual(unusable, [.approve, .newChat, .steer, .stop])
    XCTAssertFalse(unusable.contains(.markRead), "view was granted")
  }

  /// Local actions cost nothing and stay usable on a grant reduced to nothing,
  /// exactly as the command keys already behave.
  func testLocalActionsNeedNoCapability() {
    for action in [KeyAction.previousAgent, .nextAgent, .pushToTalk, .none] {
      XCTAssertNil(action.requiredCapability, action.rawValue)
    }
    let layout = KeyLayout(actions: [.previousAgent, .nextAgent, .pushToTalk, .none, .none, .none])
    XCTAssertTrue(layout.unusableActions(given: []).isEmpty)
  }

  /// The hardware cannot stop you fitting two identical caps, and a second
  /// stop key within thumb reach is a reasonable thing to want.
  func testTheSameActionMayOccupyTwoPositions() {
    let layout = KeyLayout.default.assigning(.stop, to: 0).assigning(.stop, to: 5)

    XCTAssertEqual(layout.action(at: 0), .stop)
    XCTAssertEqual(layout.action(at: 5), .stop)
  }

  func testLayoutsNormaliseLengthAndSurviveCoding() throws {
    XCTAssertEqual(KeyLayout(actions: []).actions.count, 6)
    XCTAssertEqual(KeyLayout(actions: Array(repeating: .stop, count: 20)).actions.count, 6)

    let layout = KeyLayout.default.assigning(.newChat, to: 3)
    let decoded = try JSONDecoder().decode(
      KeyLayout.self, from: try JSONEncoder().encode(layout))
    XCTAssertEqual(decoded, layout)
  }

  /// A blank key is different from a key whose action the device may not
  /// perform: one is a choice, the other is a refusal.
  func testABlankKeyIsNotAnUnusableKey() {
    let layout = KeyLayout(actions: [.none, .none, .none, .none, .none, .none])

    XCTAssertTrue(layout.unusableActions(given: []).isEmpty)
    XCTAssertEqual(layout.action(at: 0), KeyAction.none)
  }

  /// The default layout must work for a device that can only observe,
  /// otherwise a freshly paired phone shows a pad of dead keys.
  func testTheDefaultLayoutIsUsableByAFreshlyPairedDevice() {
    let unusable = KeyLayout.default.unusableActions(given: [.view])

    XCTAssertEqual(unusable, [.stop, .steer])
    XCTAssertLessThan(unusable.count, 4, "most of the default pad was dead on arrival")
  }
}
