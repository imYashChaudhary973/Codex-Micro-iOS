import CompanionProtocol
import Foundation
import XCTest

/// Joystick workflows.
///
/// A workflow is a prompt, not a privilege: it spends exactly the capability
/// typing the words by hand would, and the Mac resolves sandbox, roots, and
/// approval policy for it like any other turn. These tests pin that, and pin
/// the wording rules that keep a thumb-flick's blast radius predictable.
final class JoystickWorkflowTests: XCTestCase {

  func testEveryDirectionHasExactlyOneWorkflow() {
    for direction in JoystickWorkflow.Direction.allCases {
      XCTAssertNotNil(JoystickWorkflow.workflow(for: direction), direction.rawValue)
    }
    XCTAssertEqual(
      Set(JoystickWorkflow.allCases.map(\.direction)).count,
      JoystickWorkflow.allCases.count,
      "two workflows share a direction")
  }

  /// A workflow must not be able to ask for more than the prompt sheet could.
  func testEveryWorkflowSpendsOnlyRunAgent() {
    for workflow in JoystickWorkflow.allCases {
      XCTAssertEqual(workflow.requiredCapability, .runAgent, workflow.rawValue)
    }
  }

  /// The control is used without deliberation, so a macro that expands to
  /// "fix everything" is one whose blast radius the user cannot predict from a
  /// flick of a thumb.
  func testPromptsAreScopedRatherThanOpenEnded() {
    for workflow in JoystickWorkflow.allCases {
      let prompt = workflow.prompt.lowercased()
      XCTAssertFalse(prompt.isEmpty, workflow.rawValue)
      for unbounded in ["everything", "all files", "whatever", "anything you"] {
        XCTAssertFalse(prompt.contains(unbounded), "\(workflow.rawValue) is open-ended")
      }
    }
  }

  /// Review explicitly says not to change files: it is the one workflow whose
  /// name implies reading and whose default would otherwise be ambiguous.
  func testReviewSaysNotToChangeFiles() {
    XCTAssertTrue(JoystickWorkflow.review.prompt.lowercased().contains("do not change"))
  }

  // MARK: - Availability

  /// A workflow starts a turn rather than steering one, so a finished agent is
  /// the normal case for it rather than a refusal.
  func testAFinishedAgentCanStillReceiveAWorkflow() {
    let availability = JoystickWorkflow.availability(
      in: surface(activity: .finished), capabilities: [.runAgent])

    XCTAssertEqual(availability, .available)
  }

  func testAWorkflowNeedsRunAgentASelectionAndALiveFeed() {
    XCTAssertEqual(
      JoystickWorkflow.availability(in: surface(), capabilities: [.view]), .notPermitted)
    XCTAssertEqual(
      JoystickWorkflow.availability(in: surface(selected: nil), capabilities: [.runAgent]),
      .noSelection)
    XCTAssertEqual(
      JoystickWorkflow.availability(
        in: surface(freshness: .stale), capabilities: [.runAgent]), .notLive)
    XCTAssertEqual(
      JoystickWorkflow.availability(in: .disconnected, capabilities: [.runAgent]), .notLive)
  }

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
