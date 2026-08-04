import CompanionProtocol
import Foundation
import XCTest

/// The accept and reject keys.
///
/// The gate for this step is that it must be impossible to approve something
/// the screen did not show. These tests are that gate.
final class ApprovalKeyTests: XCTestCase {

  /// The decision is built from the presented request, digest included, so
  /// there is no path where a key sends an identifier the screen never
  /// displayed.
  func testTheCommandCarriesThePresentedRequestsOwnDigest() throws {
    let request = try approval(digest: "digest-shown")
    let keys = ApprovalKeyState.resolve(
      pending: [request], surface: surface(), capabilities: [.approve])

    guard
      case .resolveApproval(let requestID, let decision, let digest)? =
        keys.command(for: .approveOnce)
    else {
      XCTFail("no command was produced")
      return
    }
    XCTAssertEqual(requestID, request.requestID)
    XCTAssertEqual(decision, .approveOnce)
    XCTAssertEqual(digest, "digest-shown")
  }

  func testNothingPresentedProducesNoCommand() {
    let keys = ApprovalKeyState.resolve(
      pending: [], surface: surface(), capabilities: [.approve])

    XCTAssertNil(keys.command(for: .approveOnce))
    XCTAssertEqual(keys.unavailability, .noPendingApproval)
  }

  /// A key cannot invent a decision the Mac did not list.
  func testADecisionTheRequestDoesNotOfferProducesNoCommand() throws {
    let keys = ApprovalKeyState.resolve(
      pending: [try approval(decisions: [.decline])],
      surface: surface(), capabilities: [.approve])

    XCTAssertNil(keys.command(for: .approveOnce))
    XCTAssertNotNil(keys.command(for: .decline))
  }

  /// Resolving an approval from another thread would answer a question the
  /// user is not looking at.
  func testAnApprovalForAnotherAgentIsNotOffered() throws {
    let keys = ApprovalKeyState.resolve(
      pending: [try approval(threadID: "thread-other")],
      surface: surface(), capabilities: [.approve])

    XCTAssertEqual(keys.unavailability, .notForSelectedAgent)
    XCTAssertNil(keys.command(for: .approveOnce))
  }

  func testApprovingNeedsTheCapabilityALiveFeedAndAConnection() throws {
    let request = [try approval()]

    XCTAssertEqual(
      ApprovalKeyState.resolve(
        pending: request, surface: surface(), capabilities: [.view]
      ).unavailability,
      .notPermitted)
    XCTAssertEqual(
      ApprovalKeyState.resolve(
        pending: request, surface: surface(freshness: .stale),
        capabilities: [.approve]
      ).unavailability,
      .notLive)
    XCTAssertEqual(
      ApprovalKeyState.resolve(
        pending: request, surface: .disconnected, capabilities: [.approve]
      ).unavailability,
      .notLive)
  }

  /// Undisclosed content is a legitimate state, not an error. The keys stay
  /// usable and the flag lets the view say plainly that the request is not
  /// shown, so approving blind is the user's choice rather than the
  /// interface's.
  func testUndisclosedContentStillAllowsApprovalButIsReported() throws {
    let hidden = ApprovalKeyState.resolve(
      pending: [try approval()], surface: surface(), capabilities: [.approve])
    let shown = ApprovalKeyState.resolve(
      pending: [try approval(summary: "Run: swift test")],
      surface: surface(), capabilities: [.approve])

    XCTAssertTrue(hidden.isAvailable)
    XCTAssertFalse(hidden.disclosesContent)
    XCTAssertTrue(shown.disclosesContent)
  }

  private func approval(
    threadID: String = "thread-a",
    digest: String = "digest-1",
    decisions: [CompanionApprovalDecision] = [.approveOnce, .decline],
    summary: String? = nil
  ) throws -> SecureApprovalRequest {
    try SecureApprovalRequest(
      requestID: "request-1", threadID: threadID, projectID: "project-a",
      kind: .command, availableDecisions: decisions, requestDigest: digest,
      expiresAtEpochSeconds: 10_000, summary: summary)
  }

  private func surface(freshness: AgentKeyFreshness = .live) -> DeviceSurfaceState {
    var keys = [
      AgentKeyState(
        slot: 0, threadID: "thread-a", projectID: "project-a",
        activity: .waiting, freshness: freshness)
    ]
    keys.append(contentsOf: (1..<AgentKeyState.slotCount).map { AgentKeyState.unbound(slot: $0) })
    return DeviceSurfaceState(agentKeys: keys, selectedSlot: 0, isConnected: true)
  }
}
