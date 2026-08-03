import CompanionProtocol
import CryptoKit
import Foundation

/// The **semantic** digest that identifies what a command asks for, fixed by
/// plan §2 invariant 12.
///
/// It covers exactly the command type, the normalized target, the payload,
/// and the effective policy the Mac resolved. It deliberately excludes:
///
/// - the command ID, which is the ledger *key*, not part of what is asked;
/// - `issuedAt`, so a device that retries the same command after a reconnect
///   produces the same digest rather than a collision;
/// - session IDs, connection IDs, and frame counters, which change on every
///   reconnect and say nothing about the request.
///
/// This is why it is not ``CommandFingerprint``. That digest hashes the whole
/// `ClientCommand` including `issuedAt` and is the Phase 1 approval path's
/// notion of identity; reusing it here would make an honest retry look like a
/// digest collision and fail closed on a device that did nothing wrong.
///
/// The encoding is canonical: a leading version byte, a length-prefixed ASCII
/// domain separator, then fixed-order length-prefixed fields, so no two
/// distinct commands can collide by concatenation.
public enum SemanticCommandDigest {
  static let version: UInt8 = 1
  static let domain = "codex-micro/semantic-command/v1"

  /// Computes the digest of one command under the effective policy the Mac
  /// resolved for it.
  ///
  /// - Parameters:
  ///   - command: The strictly decoded command.
  ///   - projectID: The Mac-resolved project the target belongs to, or `nil`
  ///     for a command whose target carries no project.
  ///   - effectiveProfile: The mobile action profile the Mac resolved.
  public static func digest(
    of command: ClientCommand,
    projectID: String?,
    effectiveProfile: MobileActionProfile
  ) -> String {
    var bytes = Data([version])
    append(Data(domain.utf8), to: &bytes)
    append(Data(command.body.kind.rawValue.utf8), to: &bytes)
    append(Data((projectID ?? "").utf8), to: &bytes)
    append(Data(effectiveProfile.rawValue.utf8), to: &bytes)
    for field in targetAndPayload(of: command.body) {
      append(field, to: &bytes)
    }
    return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
  }

  /// The normalized target and payload of one command body, in fixed order.
  private static func targetAndPayload(of body: ClientCommandBody) -> [Data] {
    switch body {
    case .selectThread(let threadID):
      return [Data(threadID.utf8)]
    case .startThread(let projectID, let prompt, let attachmentIDs):
      return [Data(projectID.utf8), Data(prompt.utf8)]
        + attachmentIDs.sorted().map {
          Data($0.utf8)
        }
    case .sendPrompt(let threadID, let prompt, let attachmentIDs):
      return [Data(threadID.utf8), Data(prompt.utf8)]
        + attachmentIDs.sorted().map {
          Data($0.utf8)
        }
    case .steerTurn(let threadID, let turnID, let prompt):
      return [Data(threadID.utf8), Data(turnID.utf8), Data(prompt.utf8)]
    case .interruptTurn(let threadID, let turnID):
      return [Data(threadID.utf8), Data(turnID.utf8)]
    case .resolveApproval(let requestID, let decision, let requestDigest):
      return [Data(requestID.utf8), Data(decision.rawValue.utf8), Data(requestDigest.utf8)]
    case .markThreadRead(let threadID, let throughSequence):
      return [
        Data(threadID.utf8),
        Data(withUnsafeBytes(of: throughSequence.bigEndian) { Array($0) }),
      ]
    }
  }

  /// Appends one field with a big-endian `UInt32` byte-length prefix, so no
  /// field boundary can be forged by moving bytes between neighbours.
  private static func append(_ field: Data, to bytes: inout Data) {
    withUnsafeBytes(of: UInt32(field.count).bigEndian) { bytes.append(contentsOf: $0) }
    bytes.append(field)
  }
}
