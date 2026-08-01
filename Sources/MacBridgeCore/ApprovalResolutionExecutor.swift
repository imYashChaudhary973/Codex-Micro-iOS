import CodexAppServer
import CompanionProtocol
import Foundation

/// The app-server operations approval execution needs, satisfied by the live
/// `CodexAppServerClient` and by test doubles.
public protocol CodexApprovalResponding: Sendable {
  func respondToServerRequest(id: Int64, result: JSONValue) async throws
  func interruptTurn(threadID: String, turnID: String) async throws
}

extension CodexAppServerClient: CodexApprovalResponding {
  public func interruptTurn(threadID: String, turnID: String) async throws {
    _ = try await request(
      method: "turn/interrupt",
      params: .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
      ])
    )
  }
}

extension CodexRuntimeSupervisor: CodexApprovalResponding {}

public enum ApprovalExecutionError: Error, Equatable, Sendable {
  case unsupportedCommand
}

/// The closed set of ways one `resolveApproval` command can end. Every case
/// carries the final content-free ledger record.
public enum ApprovalResolutionOutcome: Equatable, Sendable {
  /// The response was sent and Codex confirmed it via `serverRequest/resolved`.
  case confirmed(CommandLedgerRecord)
  /// The command ID was seen before; the recorded result is returned without
  /// executing anything again.
  case replayed(CommandLedgerRecord)
  /// Policy rejected the resolution before anything was sent.
  case rejectedByPolicy(CommandLedgerRecord, PendingApprovalError)
  /// The response could not be handed to the app-server; nothing was sent and
  /// the command is terminally failed. The approval still needs review on the
  /// Mac because its registry record can no longer be answered from the phone.
  case sendFailed(CommandLedgerRecord)
  /// The response was sent but Codex never confirmed resolution. Nothing is
  /// resent; the user reviews the true outcome on the Mac.
  case outcomeUnknown(CommandLedgerRecord)
}

/// Executes phone-originated `resolveApproval` commands against the live
/// app-server: ledger `submitting` → policy-gated preparation → single send →
/// ledger `submitted` → `serverRequest/resolved` reconciliation → terminal
/// outcome. Ambiguity is always surfaced as `outcomeUnknown`; a response is
/// never sent twice and never sent after a policy rejection.
public actor ApprovalResolutionExecutor {
  private let store: CodexDomainStore
  private let ledger: any CommandLedgering
  private let responder: any CodexApprovalResponding
  private let resolutionTimeout: Duration

  private var pendingExecutions: Set<String> = []
  private var bufferedResolutions: Set<String> = []
  private var waiters: [String: CheckedContinuation<Bool, Never>] = [:]

  public init(
    store: CodexDomainStore,
    ledger: any CommandLedgering,
    responder: any CodexApprovalResponding,
    resolutionTimeout: Duration = .seconds(10)
  ) {
    self.store = store
    self.ledger = ledger
    self.responder = responder
    self.resolutionTimeout = resolutionTimeout
  }

  /// Feed every `serverRequest/resolved` notification here from the event
  /// pump. Resolutions for requests with no in-flight execution are only
  /// buffered while that execution is between preparation and its await, so
  /// the set stays bounded.
  public func noteServerRequestResolved(requestID: String) {
    if let waiter = waiters.removeValue(forKey: requestID) {
      waiter.resume(returning: true)
    } else if pendingExecutions.contains(requestID) {
      bufferedResolutions.insert(requestID)
    }
  }

  public func execute(
    command: ClientCommand,
    deviceID: UUID,
    userPresence: ApprovalUserPresenceProof? = nil,
    now: Date = Date()
  ) async throws -> ApprovalResolutionOutcome {
    guard
      case .resolveApproval(let requestID, let decision, let requestDigest) = command.body
    else {
      throw ApprovalExecutionError.unsupportedCommand
    }

    switch try await ledger.register(deviceID: deviceID, command: command, at: now) {
    case .replay(let record):
      return .replayed(record)
    case .accepted:
      break
    }

    let prepared: PreparedApprovalResolution
    do {
      prepared = try await store.prepareApprovalResolution(
        requestID: requestID,
        requestDigest: requestDigest,
        decision: decision,
        userPresence: userPresence,
        now: now
      )
    } catch let error as PendingApprovalError {
      try await ledger.finish(
        commandID: command.commandID,
        state: .declined,
        resultCode: .rejectedByPolicy,
        at: now
      )
      return .rejectedByPolicy(try await currentRecord(command.commandID), error)
    }

    pendingExecutions.insert(requestID)
    defer {
      pendingExecutions.remove(requestID)
      bufferedResolutions.remove(requestID)
    }

    do {
      try await responder.respondToServerRequest(
        id: prepared.rpcID,
        result: prepared.response
      )
    } catch {
      try? await store.markApprovalOutcomeUnknown(requestID: requestID)
      try await ledger.finish(
        commandID: command.commandID,
        state: .failed,
        resultCode: .codexUnavailable,
        at: now
      )
      return .sendFailed(try await currentRecord(command.commandID))
    }

    try await ledger.markSubmitted(
      commandID: command.commandID,
      threadID: prepared.threadID,
      turnID: prepared.turnID,
      requestID: requestID,
      at: now
    )

    if prepared.shouldInterruptTurn {
      // Best-effort: a failed interrupt must not block reconciliation of the
      // resolution itself; a dead connection surfaces below as outcomeUnknown.
      try? await responder.interruptTurn(
        threadID: prepared.threadID,
        turnID: prepared.turnID
      )
    }

    guard await awaitResolution(requestID: requestID) else {
      try? await store.markApprovalOutcomeUnknown(requestID: requestID)
      try await ledger.markOutcomeUnknown(
        commandID: command.commandID,
        resultCode: .confirmationTimedOut,
        at: now
      )
      return .outcomeUnknown(try await currentRecord(command.commandID))
    }

    await store.markApprovalResolved(requestID: requestID)
    try await ledger.finish(
      commandID: command.commandID,
      state: .succeeded,
      resultCode: .completed,
      at: now
    )
    return .confirmed(try await currentRecord(command.commandID))
  }

  private func awaitResolution(requestID: String) async -> Bool {
    if bufferedResolutions.remove(requestID) != nil { return true }

    let timeoutTask = Task { [resolutionTimeout] in
      try? await Task.sleep(for: resolutionTimeout)
      self.timeOutWaiter(requestID: requestID)
    }
    let confirmed = await withCheckedContinuation { continuation in
      waiters[requestID] = continuation
    }
    timeoutTask.cancel()
    return confirmed
  }

  private func timeOutWaiter(requestID: String) {
    waiters.removeValue(forKey: requestID)?.resume(returning: false)
  }

  private func currentRecord(_ commandID: UUID) async throws -> CommandLedgerRecord {
    guard let record = await ledger.record(commandID: commandID) else {
      throw CommandLedgerError.missingCommand
    }
    return record
  }
}
