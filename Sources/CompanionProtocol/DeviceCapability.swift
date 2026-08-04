import Foundation

/// What a paired device is permitted to do.
///
/// This lives in `CompanionProtocol` rather than beside the policy that
/// enforces it because it is a **wire vocabulary**: it is written into grant
/// blobs, and the device is told its own capability set so the surface can
/// show an unavailable control as unavailable rather than as one that fails
/// when pressed (Phase 3 invariant 2).
///
/// Keeping one definition matters more than the tidiness of where it sits.
/// The phone cannot import `MacBridgeCore`, so the alternative was a mirrored
/// copy — and mirrored vocabularies have diverged three times in this project,
/// each time producing a failure that looked like a transport problem.
public enum DeviceCapability: String, Codable, CaseIterable, Hashable, Sendable {
  /// Observe threads in the granted projects.
  case view
  /// Reply to a running turn.
  case respond
  /// Start or steer agent work.
  case runAgent
  /// Resolve an approval request.
  case approve
  /// Interrupt a running turn.
  case interrupt
  /// Create a new thread.
  case startThread
}
