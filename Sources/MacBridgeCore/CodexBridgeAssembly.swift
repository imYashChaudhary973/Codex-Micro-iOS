import CodexAppServer
import CompanionProtocol
import Foundation

/// Content-free domain changes recorded in the bounded event journal. Opaque
/// IDs only, matching what companion snapshots already expose.
public enum BridgeDomainEvent: Equatable, Sendable {
  case threadUpdated(threadID: String)
}

/// What the hosting app observes: forwarded recovery/runtime milestones plus
/// a tick whenever domain state changed and a fresh snapshot is worth
/// pulling.
public enum BridgeUpdate: Equatable, Sendable {
  case recovery(CodexRecoveryEvent)
  case stateChanged(latestSequence: UInt64)
}

/// Resolves the encrypted command ledger's production location under the
/// user's Application Support directory.
public enum BridgeLedgerFactory {
  public static func applicationSupportDatabaseURL(base: URL? = nil) throws -> URL {
    let support =
      try base
      ?? FileManager.default.url(
        for: .applicationSupportDirectory,
        in: .userDomainMask,
        appropriateFor: nil,
        create: true
      )
    return
      support
      .appendingPathComponent("CodexMicro", isDirectory: true)
      .appendingPathComponent("command-ledger.sqlite")
  }

  public static func keychainBackedLedger(
    databaseURL: URL? = nil
  ) throws -> PersistentCommandLedger {
    try PersistentCommandLedger.keychainBacked(
      databaseURL: databaseURL ?? applicationSupportDatabaseURL()
    )
  }
}

/// The composition root the Mac app hosts: one supervised runtime with
/// automatic recovery, the actor-isolated domain store, the bounded event
/// journal, approval execution, and redacted logging, all wired behind a
/// small lifecycle. The assembly is the single consumer of the supervisor's
/// and recovery coordinator's streams; the app observes `updates`.
public actor CodexBridgeAssembly {
  public struct Configuration: Sendable {
    public var journalCapacity: Int
    public var resolutionTimeout: Duration
    public var restartDelay: Duration
    public var maximumRestartDelay: Duration

    public init(
      journalCapacity: Int = 10_000,
      resolutionTimeout: Duration = .seconds(10),
      restartDelay: Duration = .seconds(1),
      maximumRestartDelay: Duration = .seconds(30)
    ) {
      self.journalCapacity = journalCapacity
      self.resolutionTimeout = resolutionTimeout
      self.restartDelay = restartDelay
      self.maximumRestartDelay = maximumRestartDelay
    }
  }

  public nonisolated let updates: AsyncStream<BridgeUpdate>

  private let supervisor: CodexRuntimeSupervisor
  private let store: CodexDomainStore
  private let ledger: any CommandLedgering
  private let journal: EventJournal<BridgeDomainEvent>
  private let executor: ApprovalResolutionExecutor
  private let recovery: CodexRuntimeRecoveryCoordinator
  private let logger: RedactedLogger
  private let updateContinuation: AsyncStream<BridgeUpdate>.Continuation
  private var eventPumpTask: Task<Void, Never>?
  private var recoveryPumpTask: Task<Void, Never>?
  private var running = false

  public init(
    supervisor: CodexRuntimeSupervisor,
    ledger: any CommandLedgering,
    logger: RedactedLogger = RedactedLogger(),
    configuration: Configuration = Configuration()
  ) throws {
    self.supervisor = supervisor
    self.ledger = ledger
    self.logger = logger
    let store = CodexDomainStore()
    self.store = store
    journal = try EventJournal(capacity: configuration.journalCapacity)
    executor = ApprovalResolutionExecutor(
      store: store,
      ledger: ledger,
      responder: supervisor,
      resolutionTimeout: configuration.resolutionTimeout
    )
    recovery = CodexRuntimeRecoveryCoordinator(
      supervisor: supervisor,
      store: store,
      ledger: ledger,
      restartDelay: configuration.restartDelay,
      maximumRestartDelay: configuration.maximumRestartDelay
    )
    let pair = AsyncStream<BridgeUpdate>.makeStream()
    updates = pair.stream
    updateContinuation = pair.continuation
  }

  /// Builds the production assembly: the installed Codex executable behind
  /// the compatibility gate and the Keychain-backed encrypted ledger in
  /// Application Support.
  public static func live(
    configuration: Configuration = Configuration()
  ) throws -> CodexBridgeAssembly {
    try CodexBridgeAssembly(
      supervisor: CodexRuntimeSupervisor.live(),
      ledger: BridgeLedgerFactory.keychainBackedLedger(),
      configuration: configuration
    )
  }

  // MARK: - Lifecycle

  public func start() async {
    guard !running else { return }
    running = true
    await recovery.start()
    eventPumpTask = Task { await self.pumpAppServerEvents() }
    recoveryPumpTask = Task { await self.pumpRecoveryEvents() }
    await supervisor.start()
  }

  public func stop() async {
    guard running else { return }
    running = false
    await recovery.stop()
    await supervisor.stop()
    eventPumpTask?.cancel()
    recoveryPumpTask?.cancel()
    eventPumpTask = nil
    recoveryPumpTask = nil
    updateContinuation.finish()
  }

  /// Clean pause for system sleep: the supervisor stops without entering a
  /// degraded state, so recovery does not fire.
  public func suspend() async {
    await supervisor.stop()
  }

  /// Resume after wake; the full compatibility gate runs again.
  public func resume() async {
    guard running else { return }
    await supervisor.start()
  }

  // MARK: - Companion-facing state

  public func snapshot(now: Date = Date()) async -> CompanionStateSnapshot {
    await store.makeCompanionSnapshot(
      latestSequence: await journal.latestSequence(),
      generatedAt: now,
      now: now
    )
  }

  public func replay(after cursor: UInt64) async throws -> JournalReplay<BridgeDomainEvent> {
    try await journal.replay(after: cursor)
  }

  /// The live runtime, for the network command gateway.
  ///
  /// Exposed because the gateway is the single path from a phone key to a
  /// semantic mutation and it needs something that can actually reach Codex.
  /// Handing it the supervisor rather than a new client is deliberate: the
  /// supervisor already owns compatibility, restart, and degradation, so a
  /// command is refused while Codex is unhealthy by the same logic that
  /// refuses one on the Mac.
  public nonisolated var runtime: CodexRuntimeSupervisor { supervisor }

  public func runtimeState() async -> CodexRuntimeState {
    await supervisor.state()
  }

  // MARK: - Commands

  public func resolveApproval(
    command: ClientCommand,
    deviceID: UUID,
    userPresence: ApprovalUserPresenceProof? = nil,
    now: Date = Date()
  ) async throws -> ApprovalResolutionOutcome {
    logger.log(.commandRegistered(kind: command.body.kind), at: now)
    let outcome = try await executor.execute(
      command: command,
      deviceID: deviceID,
      userPresence: userPresence,
      now: now
    )
    switch outcome {
    case .confirmed:
      logger.log(.approvalConfirmed, at: now)
    case .replayed:
      logger.log(.commandReplayed(kind: command.body.kind), at: now)
    case .rejectedByPolicy(_, let reason):
      logger.log(.approvalRejected(reason: reason), at: now)
    case .sendFailed(let record), .outcomeUnknown(let record):
      logger.log(.approvalOutcomeUnknown, at: now)
      logger.log(
        .commandFinished(
          state: record.state,
          resultCode: record.resultCode ?? .bridgeRestartedBeforeOutcome
        ),
        at: now
      )
    }
    await emitStateChanged()
    return outcome
  }

  // MARK: - Pumps

  private func pumpAppServerEvents() async {
    for await event in supervisor.events {
      guard !Task.isCancelled else { return }
      logger.log(RedactedLogger.describe(event))
      await consume(event)
    }
  }

  private func consume(_ event: AppServerEvent) async {
    do {
      switch try await store.apply(event) {
      case .updated(let threadID):
        _ = try? await journal.append(.threadUpdated(threadID: threadID))
        await emitStateChanged()
      case .snapshotRequired(let threadID):
        await rebuildThread(threadID)
      case .ignored:
        break
      }
    } catch let error as PendingApprovalError {
      logger.log(.approvalRejected(reason: error))
    } catch {
      logger.log(.eventDiscarded)
    }

    if case .notification(let method, let params) = event,
      method == "serverRequest/resolved"
    {
      let requestID =
        params["requestId"].string ?? params["requestId"].integer.map(String.init)
      if let requestID {
        await executor.noteServerRequestResolved(requestID: requestID)
      }
    }
  }

  /// Takes a thread the bridge just opened into the store.
  ///
  /// `thread/start` returns an identifier and emits no event, so a thread
  /// created through the runtime is real on Codex and invisible to the store —
  /// and therefore absent from every device snapshot. A device then has no
  /// thread to name, and a press against the one it invents is answered
  /// `codexUnavailable`. This closes that gap using the same authoritative
  /// read the event path already uses for a thread the store does not know.
  /// Returns whether the store actually took it. `rebuildThread` fails
  /// silently by design — the next event retries — but a caller adopting a
  /// thread it just created has no next event to wait for, so a silent failure
  /// there is indistinguishable from success and leaves every device with an
  /// empty world.
  @discardableResult
  public func adoptThread(_ threadID: String) async -> Bool {
    guard let thread = try? await supervisor.readThread(threadID: threadID),
      (try? await store.replaceThread(with: thread)) != nil
    else {
      return false
    }
    _ = try? await journal.append(.threadUpdated(threadID: threadID))
    await emitStateChanged()
    return true
  }

  /// Fetches the authoritative snapshot for a thread the store does not know
  /// yet. On failure nothing is stored; the next event retries the same path.
  private func rebuildThread(_ threadID: String) async {
    guard let thread = try? await supervisor.readThread(threadID: threadID),
      (try? await store.replaceThread(with: thread)) != nil
    else {
      logger.log(.eventDiscarded)
      return
    }
    _ = try? await journal.append(.threadUpdated(threadID: threadID))
    await emitStateChanged()
  }

  private func pumpRecoveryEvents() async {
    for await event in recovery.events {
      guard !Task.isCancelled else { return }
      logger.log(RedactedLogger.describe(event))
      if case .rebuilt = event {
        await emitStateChanged()
      }
      updateContinuation.yield(.recovery(event))
    }
  }

  private func emitStateChanged() async {
    updateContinuation.yield(
      .stateChanged(latestSequence: await journal.latestSequence())
    )
  }
}
