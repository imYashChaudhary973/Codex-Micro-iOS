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
  /// The exact semantic mutation allowlist. Every other kind is denied,
  /// including approvals, which stay closed for all of Phase 2.
  ///
  /// `interruptTurn` and `markThreadRead` are the P0 pair (plan §9);
  /// `sendPrompt` and `steerTurn` are P1 and are gated a second time by the
  /// grant, which must explicitly carry `.runAgent` — the pairing default does
  /// not, so a freshly paired device cannot start or steer a turn no matter
  /// what it sends. `steerTurn` is gated a **third** time, by the turn's own
  /// recorded policy.
  /// `startThread` is gated **three** times: it must be on this list, the
  /// grant must carry `.startThread` (the pairing default does not), and the
  /// Mac must have supplied a thread starter — the default refuses. Step
  /// 2.12 deferred it pending a decision on whether v1 permits new threads;
  /// the device's dedicated key answers that, and the deferral's own terms
  /// are kept: the Mac chooses the project and the sandbox, and the phone
  /// supplies only the prompt.
  public static let allowedCommandKinds: Set<CompanionCommandKind> = [
    .interruptTurn, .markThreadRead, .sendPrompt, .steerTurn, .startThread,
  ]

  private let authority: DeviceGrantAuthority
  private let attribution: any ThreadProjectAttributing
  private let ledger: any CommandLedgering
  private let sessions: any NetworkSessionVerifying
  private let runtime: any NetworkRuntimeReadiness
  private let responder: any CodexApprovalResponding
  private let turnStarter: any CodexTurnStarting
  private let threadStarter: any CodexThreadStarting
  private let turnSteerer: any CodexTurnSteering
  private let turnPolicies: TurnPolicyRegistry
  private let workspaceRoots: any WorkspaceRootResolving
  private let readCursors: DeviceReadCursorStore
  private let hostProfile: MobileActionProfile

  public init(
    authority: DeviceGrantAuthority,
    attribution: any ThreadProjectAttributing,
    ledger: any CommandLedgering,
    sessions: any NetworkSessionVerifying,
    runtime: any NetworkRuntimeReadiness,
    responder: any CodexApprovalResponding,
    turnStarter: any CodexTurnStarting,
    threadStarter: any CodexThreadStarting = DeniedThreadStarter(),
    turnSteerer: any CodexTurnSteering,
    turnPolicies: TurnPolicyRegistry = TurnPolicyRegistry(),
    workspaceRoots: any WorkspaceRootResolving = DeniedWorkspaceRootResolver(),
    readCursors: DeviceReadCursorStore,
    hostProfile: MobileActionProfile = .runWorkspace
  ) {
    self.authority = authority
    self.attribution = attribution
    self.ledger = ledger
    self.sessions = sessions
    self.runtime = runtime
    self.responder = responder
    self.turnStarter = turnStarter
    self.threadStarter = threadStarter
    self.turnSteerer = turnSteerer
    self.turnPolicies = turnPolicies
    self.workspaceRoots = workspaceRoots
    self.readCursors = readCursors
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

  /// Executes an authorized new command.
  ///
  /// The claim already exists, so every path from here **must** reach a
  /// terminal ledger state: a record left claimed is crash-ambiguous and
  /// resolves to `outcomeUnknown` on the device's next attempt.
  func perform(_ plan: ExecutionPlan, now: Date) async -> NetworkCommandOutcome {
    switch plan.command.body {
    case .markThreadRead(let threadID, let throughSequence):
      return await performMarkThreadRead(
        plan, threadID: threadID, throughSequence: throughSequence, now: now)
    case .interruptTurn(let threadID, let turnID):
      return await performInterrupt(plan, threadID: threadID, turnID: turnID, now: now)
    case .sendPrompt(let threadID, let prompt, _):
      return await performSendPrompt(plan, threadID: threadID, prompt: prompt, now: now)
    case .steerTurn(let threadID, let turnID, let prompt):
      return await performSteerTurn(
        plan, threadID: threadID, turnID: turnID, prompt: prompt, now: now)
    case .startThread(let projectID, let prompt, _):
      return await performStartThread(
        plan, projectID: projectID, prompt: prompt, now: now)
    case .selectThread, .resolveApproval:
      // Unreachable: the allowlist refused these before the claim existed.
      return await finish(
        plan, state: .declined, resultCode: .rejectedByPolicy, now: now,
        outcome: { _ in .denied(.unsupportedCommand) })
    }
  }

  /// Advances the device's own read cursor.
  ///
  /// It **never calls Codex**: the position is device-local UI state, so a
  /// degraded runtime does not deny it and no external call is made under any
  /// outcome. The store enforces device-own, scoped, and monotonic itself, so
  /// a regressing or repeated position is a denial rather than a silent no-op
  /// — a replayed command cannot quietly unread a thread.
  private func performMarkThreadRead(
    _ plan: ExecutionPlan,
    threadID: String,
    throughSequence: UInt64,
    now: Date
  ) async -> NetworkCommandOutcome {
    do {
      _ = try await readCursors.advance(
        deviceID: plan.deviceID, threadID: threadID, to: throughSequence)
    } catch let error as DeviceReadCursorError {
      return await finish(
        plan, state: .declined, resultCode: .rejectedByPolicy, now: now,
        outcome: { _ in .denied(Self.wireReason(for: error)) })
    } catch {
      return await finish(
        plan, state: .failed, resultCode: .invalidRequest, now: now,
        outcome: { .failed($0) })
    }
    return await finish(
      plan, state: .succeeded, resultCode: .completed, now: now, outcome: { .completed($0) })
  }

  /// Interrupts exactly one turn, with **at most one** `turn/interrupt` call
  /// across duplicates, retries, and reconnects.
  ///
  /// The single call is guaranteed by the claim, not by anything here: a
  /// duplicate never reaches this method because the known-result read
  /// returned first. The ledger is moved to `submitted` **before** the call so
  /// a crash between them is ambiguous in the safe direction, and a transport
  /// failure is terminal — automatic retries are disabled (invariant 13).
  private func performInterrupt(
    _ plan: ExecutionPlan,
    threadID: String,
    turnID: String,
    now: Date
  ) async -> NetworkCommandOutcome {
    do {
      try await ledger.markSubmitted(
        commandID: plan.command.commandID,
        threadID: threadID,
        turnID: turnID,
        requestID: nil,
        at: now
      )
    } catch {
      return await finish(
        plan, state: .failed, resultCode: .invalidRequest, now: now, outcome: { .failed($0) })
    }

    do {
      try await responder.interruptTurn(threadID: threadID, turnID: turnID)
    } catch {
      // The call may or may not have reached Codex. It is never retried; the
      // user confirms the true outcome on the Mac.
      try? await ledger.markOutcomeUnknown(
        commandID: plan.command.commandID, resultCode: .codexUnavailable, at: now)
      return .outcomeUnknown(await currentRecord(plan, now: now))
    }
    return await finish(
      plan, state: .succeeded, resultCode: .completed, now: now, outcome: { .completed($0) })
  }

  /// Starts exactly one phone-originated turn.
  ///
  /// Everything about *how* the turn runs is resolved on the Mac from the
  /// effective profile the gateway already intersected: sandbox, writable
  /// roots, network access, and approval policy. The phone contributes a
  /// thread and a prompt, and `ClientCommandBody` gives it no field for
  /// anything else — so there is no permissive setting to reject, only one
  /// that cannot be expressed.
  ///
  /// Unlike the interrupt, the turn identifier is unknown until the call
  /// returns, so the ledger is marked `submitted` **after** it. Both orders
  /// leave a non-terminal record if the bridge stops mid-flight, and a
  /// non-terminal record is crash-ambiguous either way — it resolves to
  /// `outcomeUnknown` and is never resent.
  /// Creates a thread and runs its first turn.
  ///
  /// Two external calls behind one command identifier, which is why the
  /// ordering matters: the thread is created first and its identifier is
  /// recorded before the turn is attempted, so a failure between them leaves
  /// a thread the user can find rather than an orphan the ledger cannot name.
  /// A turn that then fails resolves to `outcomeUnknown` for the same reason
  /// every other external call does — it may have started.
  private func performStartThread(
    _ plan: ExecutionPlan,
    projectID: String,
    prompt: String,
    now: Date
  ) async -> NetworkCommandOutcome {
    let roots = workspaceRoots.writableRoots(forProjectID: projectID)
    let policy = PhoneTurnPolicy.resolve(
      effectiveProfile: plan.effectiveProfile, writableRoots: roots)

    let threadID: String
    do {
      threadID = try await threadStarter.startThread(projectID: projectID, policy: policy)
    } catch {
      // Nothing was created, so this is a clean refusal rather than an
      // unknown: no thread exists for the user to reconcile.
      try? await ledger.markOutcomeUnknown(
        commandID: plan.command.commandID, resultCode: .codexUnavailable, at: now)
      return .outcomeUnknown(await currentRecord(plan, now: now))
    }

    let turnID: String
    do {
      turnID = try await turnStarter.startTurn(
        threadID: threadID, prompt: prompt, policy: policy)
    } catch {
      try? await ledger.markSubmitted(
        commandID: plan.command.commandID, threadID: threadID, turnID: nil,
        requestID: nil, at: now)
      try? await ledger.markOutcomeUnknown(
        commandID: plan.command.commandID, resultCode: .codexUnavailable, at: now)
      return .outcomeUnknown(await currentRecord(plan, now: now))
    }

    try? await ledger.markSubmitted(
      commandID: plan.command.commandID, threadID: threadID, turnID: turnID,
      requestID: nil, at: now)
    // Record what the turn runs under, so a later steer can be proven rather
    // than assumed — identical to the sendPrompt path, because a first turn is
    // no different from any other once it exists.
    await turnPolicies.record(
      RecordedTurnPolicy(
        threadID: threadID,
        turnID: turnID,
        effectiveProfile: plan.effectiveProfile,
        policy: policy,
        startedByDeviceID: plan.deviceID
      )
    )
    return await finish(
      plan, state: .succeeded, resultCode: .completed, now: now, outcome: { .completed($0) })
  }

  private func performSendPrompt(
    _ plan: ExecutionPlan,
    threadID: String,
    prompt: String,
    now: Date
  ) async -> NetworkCommandOutcome {
    let roots = plan.projectID.map { workspaceRoots.writableRoots(forProjectID: $0) } ?? []
    let policy = PhoneTurnPolicy.resolve(
      effectiveProfile: plan.effectiveProfile, writableRoots: roots)

    let turnID: String
    do {
      turnID = try await turnStarter.startTurn(
        threadID: threadID, prompt: prompt, policy: policy)
    } catch {
      // The turn may or may not have started. It is never retried; the user
      // confirms the true outcome on the Mac.
      try? await ledger.markOutcomeUnknown(
        commandID: plan.command.commandID, resultCode: .codexUnavailable, at: now)
      return .outcomeUnknown(await currentRecord(plan, now: now))
    }

    try? await ledger.markSubmitted(
      commandID: plan.command.commandID,
      threadID: threadID,
      turnID: turnID,
      requestID: nil,
      at: now
    )
    // Record what the turn actually runs under, so a later steer can be
    // *proven* rather than assumed (plan Step 2.11).
    await turnPolicies.record(
      RecordedTurnPolicy(
        threadID: threadID,
        turnID: turnID,
        effectiveProfile: plan.effectiveProfile,
        policy: policy,
        startedByDeviceID: plan.deviceID
      )
    )
    return await finish(
      plan, state: .succeeded, resultCode: .completed, now: now, outcome: { .completed($0) })
  }

  /// Steers exactly one in-progress turn.
  ///
  /// Steering is the one command whose authorization depends on something
  /// other than the device: the turn's **own** effective policy. A turn
  /// running more permissively than the device's current profile cannot be
  /// steered by it, and a turn the bridge cannot prove anything about — one
  /// started in the IDE, or before a restart, or evicted from the bounded
  /// registry — cannot be steered at all. Neither refusal makes an external
  /// call.
  ///
  /// Steering never widens a turn: the seam carries no policy field, so the
  /// turn keeps the sandbox, roots, network, and approval settings it began
  /// with.
  private func performSteerTurn(
    _ plan: ExecutionPlan,
    threadID: String,
    turnID: String,
    prompt: String,
    now: Date
  ) async -> NetworkCommandOutcome {
    let authorization = await turnPolicies.authorizeSteering(
      threadID: threadID,
      turnID: turnID,
      deviceEffectiveProfile: plan.effectiveProfile
    )
    guard case .success = authorization else {
      return await finish(
        plan, state: .declined, resultCode: .rejectedByPolicy, now: now,
        outcome: { _ in .denied(.actionProfileTooRestrictive) })
    }

    do {
      try await ledger.markSubmitted(
        commandID: plan.command.commandID,
        threadID: threadID,
        turnID: turnID,
        requestID: nil,
        at: now
      )
    } catch {
      return await finish(
        plan, state: .failed, resultCode: .invalidRequest, now: now, outcome: { .failed($0) })
    }

    do {
      try await turnSteerer.steerTurn(threadID: threadID, turnID: turnID, prompt: prompt)
    } catch {
      try? await ledger.markOutcomeUnknown(
        commandID: plan.command.commandID, resultCode: .codexUnavailable, at: now)
      return .outcomeUnknown(await currentRecord(plan, now: now))
    }
    return await finish(
      plan, state: .succeeded, resultCode: .completed, now: now, outcome: { .completed($0) })
  }

  /// Moves the claim to a terminal state and returns the outcome built from
  /// the persisted record. A ledger write failure here still yields a
  /// terminal outcome to the device; the record is reconciled on restart.
  private func finish(
    _ plan: ExecutionPlan,
    state: CommandLifecycleState,
    resultCode: CommandResultCode,
    now: Date,
    outcome: (CommandLedgerRecord) -> NetworkCommandOutcome
  ) async -> NetworkCommandOutcome {
    try? await ledger.finish(
      commandID: plan.command.commandID, state: state, resultCode: resultCode, at: now)
    return outcome(await currentRecord(plan, now: now))
  }

  private func currentRecord(_ plan: ExecutionPlan, now: Date) async -> CommandLedgerRecord {
    await ledger.record(commandID: plan.command.commandID) ?? plan.record
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

  /// The closed wire reason for a read-cursor refusal. A regressing or
  /// repeated position is a stale command: the device is asking for something
  /// the Mac already moved past.
  static func wireReason(for error: DeviceReadCursorError) -> SecureCommandDenialReason {
    switch error {
    case .notAuthorized: .projectNotAllowed
    case .notMonotonic, .counterOverflow: .staleCommand
    case .cursorLimitExceeded: .unsupportedCommand
    case .corruptState, .storageUnavailable: .ledgerUnavailable
    }
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
