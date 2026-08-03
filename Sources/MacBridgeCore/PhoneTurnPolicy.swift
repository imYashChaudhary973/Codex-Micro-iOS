import CodexAppServer
import Foundation

/// The bridge-resolved settings for one phone-originated turn.
///
/// **Every field is decided on the Mac.** The phone supplies a thread and a
/// prompt and nothing else: no path, no sandbox, no approval policy, no
/// network setting. That is not a convention here — `ClientCommandBody`
/// has no field for any of them, so there is no phone-supplied value to
/// ignore (threat model §; architecture: "the phone never supplies a path or
/// raw sandbox/approval setting").
///
/// Resolution only ever moves **downward**. `runWorkspace` without
/// bridge-supplied writable roots resolves to read-only rather than to an
/// unrestricted write, because the intersection rule takes the most
/// restrictive result. Phase 2 defines no way to reach a permissive mode from
/// the phone: network access is always disabled, and the approval policy is
/// never `never`.
public struct PhoneTurnPolicy: Equatable, Sendable {
  /// The closed sandbox vocabulary a phone-originated turn may run under.
  public enum Sandbox: String, Equatable, CaseIterable, Sendable {
    case readOnly
    case workspaceWrite
  }

  /// The closed approval vocabulary. `never` is deliberately absent: a phone
  /// cannot disable approvals, and Phase 2's gateway rejects `resolveApproval`
  /// besides, so an approval raised by a phone-originated turn is answered on
  /// the Mac.
  public enum Approval: String, Equatable, CaseIterable, Sendable {
    case untrusted
    case onRequest
  }

  public let sandbox: Sandbox
  /// Bridge-capped writable roots. Always empty under `readOnly`.
  public let writableRoots: [String]
  /// Always `false` in Phase 2. New network access cannot be enabled from a
  /// phone.
  public let networkAccess: Bool
  public let approvalPolicy: Approval

  /// Resolves the policy for an effective mobile action profile.
  ///
  /// - Parameters:
  ///   - effectiveProfile: The profile the gateway already intersected from
  ///     the device grant's ceiling and the host profile.
  ///   - writableRoots: The bridge-capped roots for the resolved project.
  ///     Empty means workspace-write is unavailable, and the result is
  ///     read-only.
  public static func resolve(
    effectiveProfile: MobileActionProfile,
    writableRoots: [String]
  ) -> PhoneTurnPolicy {
    guard effectiveProfile == .runWorkspace, !writableRoots.isEmpty else {
      return PhoneTurnPolicy(
        sandbox: .readOnly,
        writableRoots: [],
        networkAccess: false,
        approvalPolicy: .untrusted
      )
    }
    return PhoneTurnPolicy(
      sandbox: .workspaceWrite,
      writableRoots: writableRoots,
      networkAccess: false,
      approvalPolicy: .untrusted
    )
  }

  /// The `turn/start` parameter object for one thread and prompt.
  ///
  /// The prompt is the only phone-supplied value that reaches Codex, and it
  /// travels as typed text content — never as a tool, method, or path.
  public func turnStartParameters(threadID: String, prompt: String) -> JSONValue {
    var sandboxPolicy: [String: JSONValue] = [
      "type": .string(sandbox.rawValue),
      "networkAccess": .bool(networkAccess),
    ]
    if sandbox == .workspaceWrite {
      sandboxPolicy["writableRoots"] = .array(writableRoots.map { .string($0) })
    }
    return .object([
      "threadId": .string(threadID),
      "input": .array([
        .object(["type": .string("text"), "text": .string(prompt)])
      ]),
      "approvalPolicy": .string(approvalPolicy.rawValue),
      "sandboxPolicy": .object(sandboxPolicy),
      "summary": .string("none"),
    ])
  }
}

/// Supplies the bridge-capped writable roots for an allowlisted project.
///
/// **Fail closed by contract.** Returning an empty array means workspace-write
/// is unavailable for that project, and the turn resolves to read-only. The
/// Phase 1 app-server surface carries no project-to-path mapping, so no
/// production resolver exists yet and ``DeniedWorkspaceRootResolver`` is the
/// default — a phone-originated turn is read-only until the Mac assembly
/// supplies real roots (Step 2.13).
public protocol WorkspaceRootResolving: Sendable {
  func writableRoots(forProjectID projectID: String) -> [String]
}

/// The default: no project has writable roots, so every phone-originated turn
/// is read-only.
public struct DeniedWorkspaceRootResolver: WorkspaceRootResolving {
  public init() {}

  public func writableRoots(forProjectID projectID: String) -> [String] { [] }
}

/// Starts exactly one phone-originated turn.
///
/// Separate from ``CodexApprovalResponding`` because it is a different
/// authority: responding to an approval answers a request Codex already
/// raised, while starting a turn originates work. The production conformer is
/// ``CodexRuntimeSupervisor``, which refuses unless the runtime is `ready`.
public protocol CodexTurnStarting: Sendable {
  /// Starts one turn and returns its opaque turn identifier.
  func startTurn(
    threadID: String,
    prompt: String,
    policy: PhoneTurnPolicy
  ) async throws -> String
}

/// Steers exactly one in-progress phone-originated turn.
///
/// Kept separate from ``CodexTurnStarting`` because the authority differs:
/// starting a turn chooses a policy, while steering may only continue one
/// that already exists. Nothing on this seam can carry a policy field, so
/// steering cannot widen a turn even if a caller wanted it to.
public protocol CodexTurnSteering: Sendable {
  func steerTurn(threadID: String, turnID: String, prompt: String) async throws
}

extension CodexRuntimeSupervisor: CodexTurnSteering {}

extension CodexRuntimeSupervisor: CodexTurnStarting {
  public func startTurn(
    threadID: String,
    prompt: String,
    policy: PhoneTurnPolicy
  ) async throws -> String {
    try await readySession().startTurn(threadID: threadID, prompt: prompt, policy: policy)
  }
}
