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
  /// Reasoning effort for this turn, or `nil` to leave the thread's default
  /// alone.
  ///
  /// **This is an opaque string, not an enum, because the model decides what
  /// is valid.** Codex advertises `supportedReasoningEfforts` per model and
  /// describes the field as "a non-empty reasoning effort value advertised by
  /// the model". A fixed enum here would be a guess that happens to work
  /// until a model ships a different set, and would fail as an invalid
  /// request rather than as an unsupported option.
  public let reasoningEffort: String?

  /// Resolves the policy for an effective mobile action profile.
  ///
  /// - Parameters:
  ///   - effectiveProfile: The profile the gateway already intersected from
  ///     the device grant's ceiling and the host profile.
  ///   - writableRoots: The bridge-capped roots for the resolved project.
  ///     Empty means workspace-write is unavailable, and the result is
  ///     read-only.
  ///   - requestedEffort: What the phone's dial asked for. The Mac clamps it
  ///     against `permittedEfforts`; anything not on that list is dropped
  ///     rather than substituted, so a device can never talk the host into a
  ///     setting the host does not offer.
  ///   - permittedEfforts: What this host will allow, normally the model's own
  ///     advertised set. Empty means the dial has nothing to offer and the
  ///     thread default stands.
  public static func resolve(
    effectiveProfile: MobileActionProfile,
    writableRoots: [String],
    requestedEffort: String? = nil,
    permittedEfforts: Set<String> = []
  ) -> PhoneTurnPolicy {
    let effort = clampEffort(requestedEffort, permitted: permittedEfforts)
    guard effectiveProfile == .runWorkspace, !writableRoots.isEmpty else {
      return PhoneTurnPolicy(
        sandbox: .readOnly,
        writableRoots: [],
        networkAccess: false,
        approvalPolicy: .untrusted,
        reasoningEffort: effort
      )
    }
    return PhoneTurnPolicy(
      sandbox: .workspaceWrite,
      writableRoots: writableRoots,
      networkAccess: false,
      approvalPolicy: .untrusted,
      reasoningEffort: effort
    )
  }

  /// Drops a requested effort the host does not permit.
  ///
  /// Dropping rather than substituting is deliberate. Silently swapping in the
  /// nearest permitted value would mean the phone's dial reads one thing while
  /// the turn runs at another, and the user would have no way to notice.
  /// Dropping leaves the thread's own default, which is a setting the user
  /// chose somewhere they can see.
  static func clampEffort(_ requested: String?, permitted: Set<String>) -> String? {
    guard let requested, !requested.isEmpty, permitted.contains(requested) else { return nil }
    return requested
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
    var parameters: [String: JSONValue] = [
      "threadId": .string(threadID),
      "input": .array([
        .object(["type": .string("text"), "text": .string(prompt)])
      ]),
      "approvalPolicy": .string(approvalPolicy.rawValue),
      "sandboxPolicy": .object(sandboxPolicy),
      "summary": .string("none"),
    ]
    // The field is `effort`, confirmed against the app-server's own generated
    // schema rather than inferred: TurnStartParams describes it as "override
    // the reasoning effort for this turn and subsequent turns". Omitted
    // entirely when absent, because sending null would be an explicit
    // instruction to clear the thread's setting rather than to leave it.
    if let reasoningEffort {
      parameters["effort"] = .string(reasoningEffort)
    }
    return .object(parameters)
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
/// Creates a thread on the Mac's terms.
///
/// Step 2.12 deferred `startThread` pending a decision on whether v1 permits
/// new threads at all. The device answers that: it has a dedicated key. The
/// deferral's own conditions are kept — the Mac chooses the project and the
/// sandbox, and the phone supplies only the prompt — so reversing the decision
/// does not widen what a phone may cause.
///
/// **This is off unless the Mac turns it on.** `DeniedThreadStarter` is the
/// default, so a bridge that has not opted in refuses every attempt regardless
/// of what a grant says.
public protocol CodexThreadStarting: Sendable {
  /// Creates a thread in `projectID` and returns its opaque identifier.
  func startThread(projectID: String, policy: PhoneTurnPolicy) async throws -> String
}

/// Refuses every thread creation. The default, so the capability is inert
/// until a Mac deliberately supplies something else.
public struct DeniedThreadStarter: CodexThreadStarting {
  public init() {}

  public func startThread(projectID: String, policy: PhoneTurnPolicy) async throws -> String {
    throw CodexRuntimeRequestError.notReady
  }
}

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

extension CodexRuntimeSupervisor: CodexThreadStarting {
  /// Opens a thread on the Mac's terms.
  ///
  /// `thread/start` invokes no model and consumes no allowance: it opens a
  /// conversation Codex can then be asked to act on. The deferral's conditions
  /// are unchanged — the Mac chooses the project and resolves the policy, and
  /// the phone supplies neither — so exposing it widens nothing a device may
  /// cause. ``DeniedThreadStarter`` remains the default, so a bridge that has
  /// not opted in still refuses every attempt.
  public func startThread(projectID: String, policy: PhoneTurnPolicy) async throws -> String {
    try await readySession().startThread(projectID: projectID, policy: policy)
  }
}

extension CodexRuntimeSupervisor: CodexTurnStarting {
  public func startTurn(
    threadID: String,
    prompt: String,
    policy: PhoneTurnPolicy
  ) async throws -> String {
    try await readySession().startTurn(threadID: threadID, prompt: prompt, policy: policy)
  }
}
