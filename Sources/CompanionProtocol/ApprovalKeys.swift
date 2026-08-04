import Foundation

/// What the accept and reject keys are offering right now.
///
/// **The presented request is carried, not just its identifier.** That is the
/// mechanism behind "it is impossible to approve something the screen did not
/// show": the decision is built from the same value the view rendered, and the
/// digest travels with it. There is no path where a key sends a request ID the
/// screen never displayed, because the key has nothing else to send.
public struct ApprovalKeyState: Equatable, Sendable {
  /// The approval the keys would act on, or `nil` when there is none.
  public let presented: SecureApprovalRequest?
  /// Why the keys cannot be used, or `nil` when they can.
  public let unavailability: Unavailability?

  public enum Unavailability: String, Equatable, Sendable {
    case noPendingApproval
    case notPermitted
    case notLive
    /// The approval is for an agent other than the selected one. Acting on it
    /// would resolve something the user is not looking at.
    case notForSelectedAgent
  }

  public var isAvailable: Bool { unavailability == nil && presented != nil }

  /// Whether the user has been shown what they would be approving.
  ///
  /// False is a legitimate state, not an error: the Mac may decline to
  /// disclose content. The keys stay usable, and the view must say plainly
  /// that the request is not shown, so approving blind is a choice the user
  /// makes rather than one the interface makes for them.
  public var disclosesContent: Bool { presented?.disclosesContent == true }

  public init(presented: SecureApprovalRequest?, unavailability: Unavailability?) {
    self.presented = presented
    self.unavailability = unavailability
  }

  /// Resolves the keys for the current surface and pending set.
  public static func resolve(
    pending: [SecureApprovalRequest],
    surface: DeviceSurfaceState,
    capabilities: Set<DeviceCapability>
  ) -> ApprovalKeyState {
    guard surface.isConnected else {
      return ApprovalKeyState(presented: nil, unavailability: .notLive)
    }
    guard capabilities.contains(.approve) else {
      return ApprovalKeyState(presented: nil, unavailability: .notPermitted)
    }
    guard let key = surface.selectedKey, let threadID = key.threadID else {
      return ApprovalKeyState(presented: nil, unavailability: .noPendingApproval)
    }
    guard key.freshness == .live else {
      return ApprovalKeyState(presented: nil, unavailability: .notLive)
    }
    guard !pending.isEmpty else {
      return ApprovalKeyState(presented: nil, unavailability: .noPendingApproval)
    }
    // Only an approval on the selected agent's thread. Resolving one from
    // another thread would answer a question the user is not looking at, which
    // is the same surprise as a key that rebinds itself — with consequences.
    guard let match = pending.first(where: { $0.threadID == threadID }) else {
      return ApprovalKeyState(presented: nil, unavailability: .notForSelectedAgent)
    }
    return ApprovalKeyState(presented: match, unavailability: nil)
  }

  /// Builds the command body for a decision on the presented request.
  ///
  /// Returns `nil` when nothing is presented or the decision is not one the
  /// request offers — a key cannot invent a decision the Mac did not list.
  public func command(for decision: CompanionApprovalDecision) -> ClientCommandBody? {
    guard isAvailable, let presented else { return nil }
    guard presented.availableDecisions.contains(decision) else { return nil }
    return .resolveApproval(
      requestID: presented.requestID,
      decision: decision,
      requestDigest: presented.requestDigest
    )
  }
}
