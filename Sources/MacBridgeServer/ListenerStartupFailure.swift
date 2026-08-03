import Foundation

/// Closed fail-closed startup vocabulary (plan §2 invariant 2 and §7 gate 1).
///
/// Each case is an independent prerequisite; any one of them disables LAN
/// entirely. No case carries a system error, path, endpoint, or identifier.
public enum ListenerStartupFailure: String, Error, Equatable, CaseIterable, Sendable {
  /// The listener is off (the default) and was not enabled by internal
  /// test configuration. Step 2.13 owns user-accessible enablement.
  case notEnabled
  /// The host or TLS identity is missing, invalid, or unavailable.
  case identityUnavailable
  /// The device-grant authority is missing, corrupt, rolled back, or
  /// otherwise unavailable.
  case grantAuthorityUnavailable
  /// The network configuration exposes no eligible interface/address.
  case networkConfigurationIneligible
  /// A live interface object could not be pinned for the binding.
  case liveInterfaceUnavailable
  /// The authorization policy is unavailable.
  case policyUnavailable
  /// The installed Codex is unsupported.
  case codexUnsupported
  /// The configured ceilings exceed the ADR §9 values.
  case ceilingsExceedADR
  /// The configured ceilings are individually inside the ADR but mutually
  /// inconsistent — for example a ping cadence tightened to inside the
  /// authentication deadline, which would let an unauthenticated peer reach
  /// the server-originated keep-alive path.
  case ceilingsInconsistent
}
