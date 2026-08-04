import CompanionProtocol
import Foundation

/// Decides which approvals a device may see and resolve.
///
/// **Approval is the highest-privilege action in this product**, and it gets
/// its own authorization rather than riding observation's. The distinction is
/// not bureaucratic: a device that may *watch* a project is being told what
/// happened, while a device that may *approve* in it is being allowed to cause
/// a real filesystem or network action. Those are different grants and the
/// code says so.
///
/// Three conditions, all required, none inferred from the others:
///
/// 1. The grant carries `.approve`. The pairing default does not, so a freshly
///    paired device sees no approvals at all.
/// 2. The approval's project is in the device's permitted set — the same
///    scoping observation uses, deliberately, so there is one answer to "what
///    can this device see" rather than two that can drift.
/// 3. The device may observe at all. A revoked or tombstoned grant discloses
///    nothing, and approvals are not an exception to that.
public struct ApprovalAuthorization: Sendable {
  /// Why a device may not act on an approval.
  public enum Refusal: String, Equatable, Sendable {
    case capabilityMissing
    case projectNotAllowed
    case notObservable
    case requestUnknown
    case requestChanged
    case requestExpired
  }

  private let scope: AuthorizedViewScope

  public init(scope: AuthorizedViewScope) {
    self.scope = scope
  }

  /// Whether this device may be shown approvals in `projectID`.
  public func maySee(projectID: String) -> Refusal? {
    guard scope.allowsObservation else { return .notObservable }
    guard scope.capabilities.contains(.approve) else { return .capabilityMissing }
    guard scope.permittedProjectIDs.contains(projectID) else { return .projectNotAllowed }
    return nil
  }

  /// Filters a set of pending approvals down to what this device may see.
  ///
  /// Approvals outside scope are **absent**, not redacted and not counted —
  /// the same rule the observation projection follows, for the same reason: a
  /// count is itself a disclosure about activity in a project the device was
  /// not granted.
  public func visible(_ pending: [SecureApprovalRequest]) -> [SecureApprovalRequest] {
    guard scope.allowsObservation, scope.capabilities.contains(.approve) else { return [] }
    return pending.filter { scope.permittedProjectIDs.contains($0.projectID) }
  }

  /// Whether this device may resolve a specific approval.
  ///
  /// The digest is the mechanism that makes "it is impossible to approve
  /// something the screen did not show" enforceable rather than aspirational.
  /// The device echoes the digest it was given; a pending request whose digest
  /// no longer matches has changed since it was displayed, and the decision
  /// was therefore made about something else.
  public func mayResolve(
    requestID: String,
    presentedDigest: String,
    against pending: SecureApprovalRequest?,
    nowEpochSeconds: UInt64
  ) -> Refusal? {
    guard let pending, pending.requestID == requestID else { return .requestUnknown }
    if let refusal = maySee(projectID: pending.projectID) { return refusal }
    // Expiry is checked before the digest so an expired request reports as
    // expired rather than as changed; they need different responses from the
    // user, and "it changed" would send them looking for an attacker.
    guard nowEpochSeconds < pending.expiresAtEpochSeconds else { return .requestExpired }
    guard Self.constantTimeDigestMatch(presentedDigest, pending.requestDigest) else {
      return .requestChanged
    }
    return nil
  }

  /// Digest comparison in constant time.
  ///
  /// The digest is not secret, but it is a value an attacker would like to
  /// guess a byte at a time, and a comparison that returns early is the
  /// standard way to let them. Constant time here costs nothing.
  static func constantTimeDigestMatch(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for (a, b) in zip(left, right) { difference |= a ^ b }
    return difference == 0
  }
}
