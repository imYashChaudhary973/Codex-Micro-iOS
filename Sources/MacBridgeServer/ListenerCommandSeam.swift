import CompanionProtocol
import Foundation

/// The closed terminal outcome of one command, as the transport sees it.
///
/// It is deliberately not ``SecureCommandResult``: that type pairs an outcome
/// with a denial reason and rejects an inconsistent pair, so building it is a
/// fallible operation. Keeping the seam on this enum means the wire value is
/// constructed in exactly one place, where a failure can close the connection
/// instead of being swallowed.
public enum ListenerCommandOutcome: Equatable, Sendable {
  case completed
  case failed
  case outcomeUnknown
  case denied(SecureCommandDenialReason)

  /// The closed wire result for this outcome.
  func wireResult(commandID: UUID) throws -> SecureCommandResult {
    switch self {
    case .completed:
      return try SecureCommandResult(
        commandID: commandID, outcome: .completed, denialReason: nil)
    case .failed:
      return try SecureCommandResult(commandID: commandID, outcome: .failed, denialReason: nil)
    case .outcomeUnknown:
      return try SecureCommandResult(
        commandID: commandID, outcome: .outcomeUnknown, denialReason: nil)
    case .denied(let reason):
      return try SecureCommandResult(
        commandID: commandID, outcome: .denied, denialReason: reason)
    }
  }
}

/// The whole surface between the transport and the Step 2.9 command gateway.
///
/// `MacBridgeServer` owns connections and sealed carriage; it owns no ledger,
/// policy, executor, or Codex handle. This protocol is the only way a network
/// message can reach a semantic mutation, and it terminates in
/// `MacBridgeCore`'s gateway — which this module still does not import.
///
/// **There is no bypass to build.** The transport cannot name an executor, a
/// runtime, or a ledger, and the command it forwards is opaque to it: which
/// commands are permitted is decided entirely behind this seam. A device that
/// sends a command the gateway does not allow receives a closed denial like
/// any other (plan §2 invariant 12).
public protocol ListenerCommandHandling: Sendable {
  /// Runs one device-originated command for an authenticated device.
  ///
  /// `deviceID` and `sessionID` come from session authentication, never from
  /// the command payload.
  func execute(
    command: ClientCommand,
    deviceID: UUID,
    sessionID: UUID
  ) async -> ListenerCommandOutcome
}

/// The fail-closed default: an unconfigured listener executes nothing.
///
/// A listener that somehow reaches the authenticated state without a wired
/// gateway denies every command rather than inventing an outcome.
public struct DenyingListenerCommandHandler: ListenerCommandHandling {
  public init() {}

  public func execute(
    command: ClientCommand,
    deviceID: UUID,
    sessionID: UUID
  ) async -> ListenerCommandOutcome {
    .denied(.unsupportedCommand)
  }
}
