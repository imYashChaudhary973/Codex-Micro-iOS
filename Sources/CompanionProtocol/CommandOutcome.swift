import Foundation

/// What the user is told after pressing a key.
///
/// **`outcomeUnknown` is a first-class result, not an error.** The gateway
/// returns it when a command was claimed but its execution could not be
/// confirmed — the runtime died mid-flight, the connection dropped after the
/// claim. The honest answer is that it may or may not have happened, and the
/// device must say so rather than picking the reassuring guess. Collapsing it
/// into "failed" would invite a retry that executes twice; collapsing it into
/// "done" would hide a command that never ran.
public enum CommandOutcome: Equatable, Sendable {
  case completed
  /// The Mac refused, with its own closed reason.
  case denied(SecureCommandDenialReason)
  /// The command was claimed but its result is genuinely unknown.
  case unknown
  /// The command never reached the Mac.
  case notSent
}

extension CommandOutcome {
  /// Maps the Mac's terminal result onto what the device reports.
  public static func from(_ result: SecureCommandResult) -> CommandOutcome {
    switch result.outcome {
    case .completed: return .completed
    case .denied: return result.denialReason.map(CommandOutcome.denied) ?? .unknown
    case .outcomeUnknown: return .unknown
    // `failed` means the runtime refused after the command was claimed, so
    // whether anything happened is still not knowable from here.
    case .failed: return .unknown
    }
  }

  /// What to show the user.
  ///
  /// Every string here is a closed reason, never a detail from the Mac: the
  /// device says what happened to *this* command and nothing about the state
  /// of the machine.
  public var message: String {
    switch self {
    case .completed: return "Done"
    case .denied(let reason): return Self.describe(reason)
    case .unknown: return "May not have run — check the Mac before retrying"
    case .notSent: return "Not sent"
    }
  }

  static func describe(_ reason: SecureCommandDenialReason) -> String {
    // A total switch: a denial reason the phone cannot name would surface as
    // a blank refusal, which is the worst possible outcome for the one
    // message whose entire job is to explain why something did not happen.
    switch reason {
    case .revokedDevice: return "This device has been revoked"
    case .capabilityMissing: return "This device is not permitted to do that"
    case .projectNotAllowed: return "That project is not shared with this device"
    case .actionProfileTooRestrictive: return "Agent work is not permitted here"
    case .staleCommand: return "Took too long — try again"
    case .runtimeUnavailable: return "Codex is not running on the Mac"
    case .ledgerUnavailable: return "The Mac could not record the command"
    case .unsupportedCommand: return "The Mac does not support that"
    case .attachmentsUnsupported: return "Attachments are not supported"
    case .approvalsUnsupported: return "Approvals are not enabled"
    case .duplicateMismatch: return "That command was already sent differently"
    }
  }
}
