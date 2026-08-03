import CompanionProtocol
import Foundation

/// The terminal outcome of one network-originated command.
public enum NetworkCommandOutcome: Equatable, Sendable {
  /// A new command executed to a terminal state.
  case completed(CommandLedgerRecord)
  /// A matching terminal ledger result was returned; nothing executed and no
  /// external call was made.
  case replayed(CommandLedgerRecord)
  /// The command was denied. Nothing executed, no external call was made, and
  /// no ledger claim survives.
  case denied(SecureCommandDenialReason)
  /// The command reached its external call but the outcome is unknown. It is
  /// never resent (plan §2 invariant 13).
  case outcomeUnknown(CommandLedgerRecord)
  /// The command failed terminally.
  case failed(CommandLedgerRecord)

  /// The closed wire result for this outcome.
  public func wireResult(commandID: UUID) throws -> SecureCommandResult {
    switch self {
    case .completed, .replayed:
      return try SecureCommandResult(
        commandID: commandID, outcome: .completed, denialReason: nil)
    case .denied(let reason):
      return try SecureCommandResult(
        commandID: commandID, outcome: .denied, denialReason: reason)
    case .outcomeUnknown:
      return try SecureCommandResult(
        commandID: commandID, outcome: .outcomeUnknown, denialReason: nil)
    case .failed:
      return try SecureCommandResult(commandID: commandID, outcome: .failed, denialReason: nil)
    }
  }
}

/// The authenticated session a command arrived on.
///
/// Every value here comes from session authentication, never from the command
/// payload. The gateway re-verifies it against the live registry and the
/// current Mac authority before doing anything else.
public struct NetworkCommandContext: Equatable, Sendable {
  public let deviceID: UUID
  public let sessionID: UUID

  public init(deviceID: UUID, sessionID: UUID) {
    self.deviceID = deviceID
    self.sessionID = sessionID
  }
}

/// Confirms a session is still the device's current, valid one.
///
/// The authenticated-session registry lives in `CompanionCrypto`, which this
/// module does not import, so the assembly that owns both adapts it here.
public protocol NetworkSessionVerifying: Sendable {
  func isCurrentSession(deviceID: UUID, sessionID: UUID) async -> Bool
}

/// Whether the Codex runtime is ready to accept a new state-changing command.
///
/// A degraded, unsupported, or restarting runtime denies **new** commands and
/// never queues them (plan §2 invariant 14).
public protocol NetworkRuntimeReadiness: Sendable {
  func isReadyForStateChange() async -> Bool
}

extension CodexRuntimeSupervisor: NetworkRuntimeReadiness {
  public func isReadyForStateChange() async -> Bool {
    if case .ready = state() { return true }
    return false
  }
}

/// The sole network→core semantic mutation path (plan §2 invariant 12).
///
/// Network code never reaches a bridge executor directly: `MacBridgeServer`
/// does not import this module, and the only surface it is given is a seam
/// that terminates here. Every authenticated mutation runs the same fixed
/// sequence, and each step's failure is a closed denial that leaves nothing
/// behind:
///
/// 1. **Current session.** The session must still be the device's current one.
/// 2. **Current Mac authority.** The grant is re-read; revoked, expired, and
///    unknown devices are denied and an unavailable authority denies outright.
/// 3. **Strict schema and allowlist.** Approvals, attachments, and every
///    command outside the P0 allowlist are rejected before anything else.
/// 4. **Device-bound identity.** The Mac resolves the target's project and
///    the effective policy, then computes the semantic digest that identifies
///    what was asked.
/// 5. **Known result before new execution.** An existing `(deviceID,
///    commandID)` record is *read*. A different digest, or another device's
///    record, fails closed. Otherwise the recorded result is returned —
///    **after** current disclosure authorization succeeds — even when the
///    original freshness window has elapsed or Codex is now degraded
///    (invariant 13). Nothing is executed again.
/// 6. **New command only.** Freshness, project scope, capability, mobile
///    profile, and runtime readiness all pass first; the ledger claim is
///    taken last, immediately before the single external call.
///
/// **Order is load-bearing, not cosmetic.** Disclosure authorization runs
/// before a known result is returned, so a device whose scope was reduced
/// after issuing a command cannot read the answer back. The known-result read
/// precedes the claim, so a command that is going to be denied leaves no
/// ledger record at all — otherwise an honest retry after the runtime
/// recovered would find its own denied claim and resolve to `outcomeUnknown`
/// instead of executing. And the claim precedes the external call, so a crash
/// between them leaves a claimed record that resolves to `outcomeUnknown`
/// rather than permitting a silent second call.
public actor NetworkCommandGateway {
  /// The exact P0 semantic mutation allowlist (plan §9). Every other kind is
  /// denied, including approvals, which stay closed for all of Phase 2.
  public static let allowedCommandKinds: Set<CompanionCommandKind> = [
    .interruptTurn, .markThreadRead,
  ]

  private let authority: DeviceGrantAuthority
  private let attribution: any ThreadProjectAttributing
  private let ledger: any CommandLedgering
  private let sessions: any NetworkSessionVerifying
  private let runtime: any NetworkRuntimeReadiness
  private let hostProfile: MobileActionProfile

  public init(
    authority: DeviceGrantAuthority,
    attribution: any ThreadProjectAttributing,
    ledger: any CommandLedgering,
    sessions: any NetworkSessionVerifying,
    runtime: any NetworkRuntimeReadiness,
    hostProfile: MobileActionProfile = .runWorkspace
  ) {
    self.authority = authority
    self.attribution = attribution
    self.ledger = ledger
    self.sessions = sessions
    self.runtime = runtime
    self.hostProfile = hostProfile
  }

  /// Runs one authenticated command through the whole sequence.
  public func execute(
    command: ClientCommand,
    context: NetworkCommandContext,
    now: Date = Date()
  ) async -> NetworkCommandOutcome {
    do {
      let authorized = try await authorize(command: command, context: context, now: now)
      switch authorized {
      case .denied(let reason):
        return .denied(reason)
      case .replay(let record):
        return await knownResult(record, now: now)
      case .execute(let plan):
        return await perform(plan, now: now)
      }
    } catch {
      return .denied(.ledgerUnavailable)
    }
  }

  // MARK: - Authorization

  /// Everything the authorization sequence resolved for a new command.
  struct ExecutionPlan: Sendable {
    let command: ClientCommand
    let deviceID: UUID
    let projectID: String?
    let effectiveProfile: MobileActionProfile
    let record: CommandLedgerRecord
  }

  enum AuthorizationResult: Sendable {
    case denied(SecureCommandDenialReason)
    case replay(CommandLedgerRecord)
    case execute(ExecutionPlan)
  }

  func authorize(
    command: ClientCommand,
    context: NetworkCommandContext,
    now: Date
  ) async throws -> AuthorizationResult {
    // 1. The session must still be the device's current one.
    guard
      await sessions.isCurrentSession(
        deviceID: context.deviceID, sessionID: context.sessionID)
    else {
      return .denied(.revokedDevice)
    }

    // 2. Current Mac authority. A grant presented by the phone is evidence,
    //    never authorization (invariant 1).
    let grant: AuthoritativeDeviceGrant
    do {
      grant = try await authority.authoritativeGrant(deviceID: context.deviceID)
    } catch DeviceGrantAuthorityError.deviceRevoked, DeviceGrantAuthorityError.deviceExpired,
      DeviceGrantAuthorityError.deviceUnknown
    {
      return .denied(.revokedDevice)
    } catch {
      return .denied(.ledgerUnavailable)
    }

    // 3. Allowlist, approvals, and attachments — before anything is claimed.
    if let refusal = Self.refusalForClosedSurface(command.body) {
      return .denied(refusal)
    }

    // 4. Resolve the target's project and the effective policy, then bind the
    //    device to the command with the semantic digest.
    let projectID = Self.targetThreadID(command.body).flatMap {
      attribution.projectID(forThreadID: $0)
    }
    let policyGrant = grant.effectivePolicyGrant
    let effectiveProfile = MobileActionProfile.mostRestrictive([
      policyGrant.actionProfile, hostProfile,
    ])
    let digest = SemanticCommandDigest.digest(
      of: command, projectID: projectID, effectiveProfile: effectiveProfile)

    // 5. Known result before new execution. This is a **read**, deliberately
    //    ahead of the claim: a command that is going to be denied must leave
    //    no ledger record at all, or an honest retry after the runtime
    //    recovers would find its own denied claim and resolve to
    //    `outcomeUnknown` instead of executing.
    if let existing = await ledger.record(commandID: command.commandID) {
      guard existing.deviceID == context.deviceID, existing.requestDigest == digest else {
        return .denied(.duplicateMismatch)
      }
      guard Self.disclosureAuthorized(projectID: projectID, grant: policyGrant) else {
        return .denied(.projectNotAllowed)
      }
      return .replay(existing)
    }

    // 6. New command: every remaining check precedes both the claim and the
    //    single external call (plan §2 invariant 13's fixed order).
    let authorization = CapabilityPolicy.authorize(
      command: command,
      grant: policyGrant,
      resolvedProjectID: projectID,
      hostProfile: hostProfile,
      now: now
    )
    guard case .allowed(let allowedProfile) = authorization else {
      guard case .denied(let reason) = authorization else {
        return .denied(.unsupportedCommand)
      }
      return .denied(Self.wireReason(for: reason))
    }
    if Self.requiresRuntime(command.body), await runtime.isReadyForStateChange() == false {
      return .denied(.runtimeUnavailable)
    }

    // 7. Claim last. The claim is still the atomic guard: a concurrent
    //    request that got here first owns the execution, and this one
    //    replays its record rather than making a second external call.
    let claim: NetworkCommandClaim
    do {
      claim = try await ledger.claim(
        deviceID: context.deviceID,
        commandID: command.commandID,
        kind: command.body.kind,
        semanticDigest: digest,
        at: now
      )
    } catch CommandLedgerError.commandIDCollision {
      return .denied(.duplicateMismatch)
    } catch {
      return .denied(.ledgerUnavailable)
    }
    guard case .claimed(let record) = claim else {
      guard case .known(let concurrent) = claim else {
        return .denied(.ledgerUnavailable)
      }
      return .replay(concurrent)
    }

    return .execute(
      ExecutionPlan(
        command: command,
        deviceID: context.deviceID,
        projectID: projectID,
        effectiveProfile: allowedProfile,
        record: record
      )
    )
  }

  /// Returns a known result without executing anything.
  ///
  /// A record that never reached a terminal state is crash-ambiguous: the
  /// bridge claimed it and may or may not have made its external call. It
  /// becomes `outcomeUnknown` and is **never resent** (plan §2 invariant 13);
  /// the user confirms the true outcome on the Mac.
  func knownResult(_ record: CommandLedgerRecord, now: Date) async -> NetworkCommandOutcome {
    guard record.state.isTerminal else {
      try? await ledger.markOutcomeUnknown(
        commandID: record.commandID,
        resultCode: .bridgeRestartedBeforeOutcome,
        at: now
      )
      let updated = await ledger.record(commandID: record.commandID) ?? record
      return .outcomeUnknown(updated)
    }
    switch record.state {
    case .succeeded:
      return .replayed(record)
    case .outcomeUnknown:
      return .outcomeUnknown(record)
    case .failed, .declined:
      return .failed(record)
    case .submitting, .submitted:
      return .outcomeUnknown(record)
    }
  }

  /// Executes an authorized new command. Step 2.9's first PR ships the
  /// sequence with an empty execution allowlist; the two P0 commands land
  /// with their own coverage.
  func perform(_ plan: ExecutionPlan, now: Date) async -> NetworkCommandOutcome {
    try? await ledger.finish(
      commandID: plan.command.commandID,
      state: .declined,
      resultCode: .rejectedByPolicy,
      at: now
    )
    return .denied(.unsupportedCommand)
  }

  // MARK: - Closed surfaces

  /// The surfaces that are closed for all of Phase 2, checked before any
  /// ledger claim exists so a rejected command leaves no trace.
  static func refusalForClosedSurface(
    _ body: ClientCommandBody
  ) -> SecureCommandDenialReason? {
    if case .resolveApproval = body {
      return .approvalsUnsupported
    }
    if !attachmentIDs(of: body).isEmpty {
      return .attachmentsUnsupported
    }
    guard allowedCommandKinds.contains(body.kind) else {
      return .unsupportedCommand
    }
    return nil
  }

  static func attachmentIDs(of body: ClientCommandBody) -> [String] {
    switch body {
    case .startThread(_, _, let attachmentIDs), .sendPrompt(_, _, let attachmentIDs):
      return attachmentIDs
    case .selectThread, .steerTurn, .interruptTurn, .resolveApproval, .markThreadRead:
      return []
    }
  }

  static func targetThreadID(_ body: ClientCommandBody) -> String? {
    switch body {
    case .selectThread(let threadID), .sendPrompt(let threadID, _, _),
      .steerTurn(let threadID, _, _), .interruptTurn(let threadID, _),
      .markThreadRead(let threadID, _):
      return threadID
    case .startThread, .resolveApproval:
      return nil
    }
  }

  /// Whether the command may reach Codex at all. A device-local mutation
  /// never does, so a degraded runtime does not deny it.
  static func requiresRuntime(_ body: ClientCommandBody) -> Bool {
    switch body {
    case .markThreadRead, .selectThread:
      return false
    case .interruptTurn, .startThread, .sendPrompt, .steerTurn, .resolveApproval:
      return true
    }
  }

  /// Whether the device may currently be told about a result for this target.
  static func disclosureAuthorized(projectID: String?, grant: DeviceGrant) -> Bool {
    guard !grant.isRevoked, grant.capabilities.contains(.view), let projectID else {
      return false
    }
    return grant.permittedProjectIDs.contains(projectID)
  }

  static func wireReason(for reason: CommandDenialReason) -> SecureCommandDenialReason {
    switch reason {
    case .revokedDevice: .revokedDevice
    case .missingCapability: .capabilityMissing
    case .projectNotAllowed, .missingProjectContext: .projectNotAllowed
    case .actionProfileTooRestrictive: .actionProfileTooRestrictive
    case .staleCommand: .staleCommand
    }
  }
}
