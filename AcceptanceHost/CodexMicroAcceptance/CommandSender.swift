import CompanionProtocol
import Foundation

/// Sends one semantic command and waits for its result.
///
/// **The command identifier is minted once per user action and reused across
/// retries.** That is what makes a retry idempotent: the Mac's ledger keys on
/// it, so a resend after a dropped connection replays the recorded outcome
/// instead of executing again. Minting a fresh identifier per attempt would
/// turn every retry into a second command, which is exactly the failure the
/// ledger exists to prevent.
public actor CommandSender {
  private let session: SessionClient

  public init(session: SessionClient) {
    self.session = session
  }

  /// Sends a command body and returns what the Mac said about it.
  ///
  /// - Parameter commandID: Reuse the same value when retrying the *same* user
  ///   action. A new action needs a new identifier.
  public func send(
    _ body: ClientCommandBody,
    commandID: UUID = UUID(),
    issuedAt: Date = Date()
  ) async -> CommandOutcome {
    let command: ClientCommand
    do {
      command = try ClientCommand(commandID: commandID, issuedAt: issuedAt, body: body)
    } catch {
      // The body failed its own validation, so nothing was sent. This is a
      // programming error on the phone rather than a refusal by the Mac, and
      // conflating the two would send someone looking at their grant.
      return .notSent
    }

    do {
      try await session.send(
        kind: .commandRequest, payload: try JSONEncoder().encode(command))
    } catch {
      return .notSent
    }

    // Wait for the result that matches this command. Observation deliveries
    // can arrive in between and must not be mistaken for it.
    do {
      while true {
        let envelope = try await session.receive()
        guard envelope.kind == .commandResult else { continue }
        let result = try JSONDecoder().decode(
          SecureCommandResult.self, from: envelope.payload)
        guard result.commandID == command.commandID else { continue }
        return CommandOutcome.from(result)
      }
    } catch {
      // The connection died after the command was sent. Whether the Mac ran it
      // is genuinely unknown, and saying "failed" here is the answer that
      // invites a double execution.
      return .unknown
    }
  }

}
