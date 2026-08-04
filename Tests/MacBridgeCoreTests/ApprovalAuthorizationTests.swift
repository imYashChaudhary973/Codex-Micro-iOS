import CompanionProtocol
import Foundation
import XCTest

@testable import MacBridgeCore

/// Approval authorization.
///
/// Approval is the highest-privilege action in the product: a device that may
/// *watch* a project is being told what happened, while a device that may
/// *approve* in it is being allowed to cause a real filesystem or network
/// action. These tests pin that the three conditions are independent and that
/// none is inferred from the others.
final class ApprovalAuthorizationTests: XCTestCase {

  // MARK: - Visibility

  /// The pairing default has no `.approve`, so a freshly paired device sees
  /// no approvals at all.
  func testObservingAProjectDoesNotImplyApprovingInIt() throws {
    let authorization = ApprovalAuthorization(
      scope: scope(capabilities: [.view], projects: ["project-a"]))

    XCTAssertEqual(authorization.maySee(projectID: "project-a"), .capabilityMissing)
    XCTAssertTrue(authorization.visible([try request(project: "project-a")]).isEmpty)
  }

  /// Approving is scoped by the same permitted-project set observation uses,
  /// so there is one answer to "what can this device see" rather than two that
  /// can drift.
  func testApprovalsOutsideTheProjectScopeAreInvisible() throws {
    let authorization = ApprovalAuthorization(
      scope: scope(capabilities: [.view, .approve], projects: ["project-a"]))

    XCTAssertEqual(authorization.maySee(projectID: "project-b"), .projectNotAllowed)
    let visible = authorization.visible([
      try request(id: "r1", project: "project-a"),
      try request(id: "r2", project: "project-b"),
    ])
    XCTAssertEqual(visible.map(\.requestID), ["r1"])
  }

  /// Absent, not counted. A count is itself a disclosure about activity in a
  /// project the device was not granted.
  func testAnOutOfScopeApprovalIsAbsentRatherThanCounted() throws {
    let authorization = ApprovalAuthorization(
      scope: scope(capabilities: [.view, .approve], projects: []))

    XCTAssertTrue(authorization.visible([try request(project: "project-a")]).isEmpty)
  }

  func testARevokedDeviceSeesNoApprovals() throws {
    let authorization = ApprovalAuthorization(
      scope: scope(
        capabilities: [.view, .approve], projects: ["project-a"], observable: false))

    XCTAssertEqual(authorization.maySee(projectID: "project-a"), .notObservable)
  }

  // MARK: - Resolution

  /// The digest is what makes "impossible to approve something the screen did
  /// not show" enforceable rather than aspirational.
  func testADigestThatNoLongerMatchesIsRefused() throws {
    let authorization = ApprovalAuthorization(
      scope: scope(capabilities: [.view, .approve], projects: ["project-a"]))
    let pending = try request(digest: "digest-after-change")

    let refusal = authorization.mayResolve(
      requestID: pending.requestID, presentedDigest: "digest-when-shown",
      against: pending, nowEpochSeconds: 1_000)

    XCTAssertEqual(refusal, .requestChanged)
  }

  func testAMatchingDigestInScopeIsPermitted() throws {
    let authorization = ApprovalAuthorization(
      scope: scope(capabilities: [.view, .approve], projects: ["project-a"]))
    let pending = try request(digest: "digest-1")

    XCTAssertNil(
      authorization.mayResolve(
        requestID: pending.requestID, presentedDigest: "digest-1",
        against: pending, nowEpochSeconds: 1_000))
  }

  /// Expired reports as expired rather than as changed: the two need
  /// different responses, and "it changed" would send the user looking for an
  /// attacker.
  func testAnExpiredRequestReportsExpiredNotChanged() throws {
    let authorization = ApprovalAuthorization(
      scope: scope(capabilities: [.view, .approve], projects: ["project-a"]))
    let pending = try request(digest: "digest-1", expiresAt: 500)

    let refusal = authorization.mayResolve(
      requestID: pending.requestID, presentedDigest: "wrong",
      against: pending, nowEpochSeconds: 1_000)

    XCTAssertEqual(refusal, .requestExpired)
  }

  func testAnUnknownRequestIsRefusedBeforeAnythingElse() {
    let authorization = ApprovalAuthorization(
      scope: scope(capabilities: [], projects: []))

    XCTAssertEqual(
      authorization.mayResolve(
        requestID: "gone", presentedDigest: "d", against: nil, nowEpochSeconds: 1),
      .requestUnknown)
  }

  func testDigestComparisonRejectsLengthAndContentDifferences() {
    XCTAssertTrue(ApprovalAuthorization.constantTimeDigestMatch("abc", "abc"))
    XCTAssertFalse(ApprovalAuthorization.constantTimeDigestMatch("abc", "abd"))
    XCTAssertFalse(ApprovalAuthorization.constantTimeDigestMatch("abc", "abcd"))
  }

  // MARK: - Helpers

  private func scope(
    capabilities: Set<DeviceCapability>,
    projects: Set<String>,
    observable: Bool = true
  ) -> AuthorizedViewScope {
    AuthorizedViewScope(
      deviceID: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
      grantRevision: 1,
      authorizedViewEpoch: 1,
      permittedProjectIDs: observable ? projects : [],
      allowsObservation: observable,
      capabilities: observable ? capabilities : [],
      reasoningEfforts: []
    )
  }

  private func request(
    id: String = "request-1",
    project: String = "project-a",
    digest: String = "digest-1",
    expiresAt: UInt64 = 10_000
  ) throws -> SecureApprovalRequest {
    try SecureApprovalRequest(
      requestID: id, threadID: "thread-a", projectID: project, kind: .command,
      availableDecisions: [.approveOnce, .decline], requestDigest: digest,
      expiresAtEpochSeconds: expiresAt)
  }
}
