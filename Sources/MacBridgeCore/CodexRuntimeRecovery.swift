import CodexAppServer
import Foundation

/// Content-free progress events for one supervised runtime with automatic
/// recovery. Forwarded runtime states and recovery milestones share one
/// stream so the hosting app observes a single ordered narrative.
public enum CodexRecoveryEvent: Equatable, Sendable {
  case runtimeState(CodexRuntimeState)
  case recoveryStarted(attempt: Int)
  case recoveryFailed(attempt: Int)
  case rebuilt(threadIDs: [String], droppedThreadIDs: [String])
}

/// Watches the runtime supervisor and recovers automatically from degraded
/// states: in-flight ledger work is surfaced as `outcomeUnknown` first, the
/// supervisor restarts through the full compatibility gate after a backoff,
/// and thread state is rebuilt only from authoritative `thread/read`
/// snapshots. State-changing commands are never replayed; threads that cannot
/// be re-read are dropped rather than guessed. An `unsupported` runtime is
/// terminal and is not retried.
///
/// The coordinator is the single consumer of `supervisor.states`; observers
/// use `events` instead.
public actor CodexRuntimeRecoveryCoordinator {
  public nonisolated let events: AsyncStream<CodexRecoveryEvent>

  private let supervisor: CodexRuntimeSupervisor
  private let store: CodexDomainStore
  private let ledger: any CommandLedgering
  private let restartDelay: Duration
  private let maximumRestartDelay: Duration
  private let eventContinuation: AsyncStream<CodexRecoveryEvent>.Continuation
  private var watchTask: Task<Void, Never>?
  private var attempt = 0

  public init(
    supervisor: CodexRuntimeSupervisor,
    store: CodexDomainStore,
    ledger: any CommandLedgering,
    restartDelay: Duration = .seconds(1),
    maximumRestartDelay: Duration = .seconds(30)
  ) {
    self.supervisor = supervisor
    self.store = store
    self.ledger = ledger
    self.restartDelay = restartDelay
    self.maximumRestartDelay = maximumRestartDelay
    let pair = AsyncStream<CodexRecoveryEvent>.makeStream()
    events = pair.stream
    eventContinuation = pair.continuation
  }

  public func start() {
    guard watchTask == nil else { return }
    watchTask = Task { await self.watch() }
  }

  public func stop() {
    watchTask?.cancel()
    watchTask = nil
    eventContinuation.finish()
  }

  private func watch() async {
    for await state in supervisor.states {
      guard !Task.isCancelled else { return }
      eventContinuation.yield(.runtimeState(state))
      if case .degraded = state {
        await recover()
      }
    }
  }

  private func recover() async {
    attempt += 1
    eventContinuation.yield(.recoveryStarted(attempt: attempt))

    // Ambiguity is surfaced before anything restarts so no in-flight command
    // can ever be mistaken for re-executable work.
    try? await ledger.markInFlightOutcomesUnknown(at: Date())

    try? await Task.sleep(for: backoffDelay(for: attempt))
    guard !Task.isCancelled else { return }

    await supervisor.start()
    guard case .ready = await supervisor.state() else {
      eventContinuation.yield(.recoveryFailed(attempt: attempt))
      return
    }

    var rebuiltThreadIDs: [String] = []
    var droppedThreadIDs: [String] = []
    let knownThreadIDs = await store.allSnapshots().map(\.threadID)
    for threadID in knownThreadIDs {
      if let thread = try? await supervisor.readThread(threadID: threadID),
        (try? await store.replaceThread(with: thread)) != nil
      {
        rebuiltThreadIDs.append(threadID)
      } else {
        await store.removeThread(threadID: threadID)
        droppedThreadIDs.append(threadID)
      }
    }

    attempt = 0
    eventContinuation.yield(
      .rebuilt(threadIDs: rebuiltThreadIDs, droppedThreadIDs: droppedThreadIDs)
    )
  }

  private func backoffDelay(for attempt: Int) -> Duration {
    var delay = restartDelay
    for _ in 1..<max(attempt, 1) {
      delay = min(delay * 2, maximumRestartDelay)
      if delay == maximumRestartDelay { break }
    }
    return delay
  }
}
