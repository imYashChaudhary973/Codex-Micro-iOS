import CompanionCrypto
import CompanionProtocol
import Foundation
import MacBridgeCore

/// Reads the bridge's journal and feeds the observation broker.
///
/// This is the piece that makes observation live rather than merely
/// implemented. `CodexBridgeAssembly` emits `stateChanged` with the journal's
/// latest sequence but not which thread moved, so the pump replays from its
/// own cursor to recover the thread identifiers, resolves each thread to a
/// project, and hands the change to the broker.
///
/// **Attribution is resolved before the broker is told.** A thread the bridge
/// has not yet attributed would be invisible to every device, and the broker
/// consumes attribution synchronously, so resolving first is what stops a
/// change being silently dropped the first time a thread is seen.
///
/// **A retention gap is not a silent skip.** When the journal has already
/// discarded everything after the pump's cursor, there is no list of thread
/// identifiers to recover. The pump jumps its cursor forward and records the
/// gap; the devices' own retention rules already turn that into a forced
/// filtered snapshot, so nothing is invented to fill it.
public actor BridgeObservationPump {
  private let broker: DeviceObservationBroker
  private let attribution: BridgeThreadAttributionResolver
  private let replay: @Sendable (UInt64) async throws -> JournalReplay<BridgeDomainEvent>
  private var cursor: UInt64 = 0
  private var pumpTask: Task<Void, Never>?
  private(set) public var retentionGapCount = 0
  private(set) public var deliveredChangeCount = 0

  public init(
    broker: DeviceObservationBroker,
    attribution: BridgeThreadAttributionResolver,
    replay: @escaping @Sendable (UInt64) async throws -> JournalReplay<BridgeDomainEvent>
  ) {
    self.broker = broker
    self.attribution = attribution
    self.replay = replay
  }

  /// Consumes an update stream until it finishes or the pump is stopped.
  public func start(updates: AsyncStream<BridgeUpdate>) {
    guard pumpTask == nil else { return }
    pumpTask = Task { [weak self] in
      for await update in updates {
        guard !Task.isCancelled else { return }
        guard case .stateChanged = update else { continue }
        await self?.drain()
      }
    }
  }

  /// Stops consuming. The cursor is kept, so a restart resumes rather than
  /// replaying the whole journal.
  public func stop() {
    pumpTask?.cancel()
    pumpTask = nil
  }

  /// Replays everything after the cursor and hands each change to the broker.
  ///
  /// Exposed so a test — and the assembly's own start-up — can pump once
  /// without driving a stream.
  @discardableResult
  public func drain() async -> [UUID] {
    let outcome: JournalReplay<BridgeDomainEvent>
    do {
      outcome = try await replay(cursor)
    } catch {
      // A cursor the journal cannot serve is not a reason to guess. The next
      // change re-reads from the same cursor.
      return []
    }

    switch outcome {
    case .snapshotRequired(let latestSequence):
      retentionGapCount += 1
      cursor = latestSequence
      return []
    case .events(let events):
      var woken: Set<UUID> = []
      for event in events {
        cursor = max(cursor, event.sequence)
        guard case .threadUpdated(let threadID) = event.event else { continue }
        // Resolve attribution first: an unattributed thread is invisible, and
        // the broker reads attribution synchronously.
        _ = await attribution.resolve(threadID: threadID)
        let devices = await broker.recordThreadChange(threadID: threadID)
        deliveredChangeCount += 1
        woken.formUnion(devices)
      }
      return Array(woken).sorted { $0.uuidString < $1.uuidString }
    }
  }

  /// The pump's current journal cursor.
  public func currentCursor() -> UInt64 { cursor }
}

/// Runs the sweeps Steps 2.5 and 2.6 deliberately left unscheduled.
///
/// Both state machines documented that their sweeps are opportunistic —
/// `sweepExpired` and `sweepInvalidSessions` run only when a caller invokes
/// them — and both recorded scheduling as assembly work. Without it an
/// abandoned pairing session holds its bootstrap secret until something else
/// happens to touch the coordinator, and an invalidated session is only
/// noticed on the device's next message.
///
/// The scheduler owns no policy. It calls the two sweeps on an interval and
/// hands the invalidated sessions to a closer, so the decision of what to
/// close stays where it was made.
public actor BridgeSweepScheduler {
  /// How often the sweeps run. Short enough that an abandoned pairing secret
  /// is cleared well inside its five-minute life, long enough to be free.
  public static let defaultInterval: Duration = .seconds(30)

  private let pairing: PairingCoordinator?
  private let sessions: SessionCoordinator?
  private let closeSession:
    @Sendable (AuthenticatedSessionIdentity, SecureCloseReason) async ->
      Void
  private let interval: Duration
  private var task: Task<Void, Never>?
  private(set) public var sweepCount = 0

  public init(
    pairing: PairingCoordinator?,
    sessions: SessionCoordinator?,
    interval: Duration = BridgeSweepScheduler.defaultInterval,
    closeSession:
      @escaping @Sendable (AuthenticatedSessionIdentity, SecureCloseReason) async ->
      Void
  ) {
    self.pairing = pairing
    self.sessions = sessions
    self.interval = interval
    self.closeSession = closeSession
  }

  /// Starts the periodic sweep.
  public func start() {
    guard task == nil else { return }
    task = Task { [weak self] in
      guard let interval = await self?.interval else { return }
      while !Task.isCancelled {
        try? await Task.sleep(for: interval)
        guard !Task.isCancelled else { return }
        await self?.sweepOnce()
      }
    }
  }

  /// Stops sweeping.
  public func stop() {
    task?.cancel()
    task = nil
  }

  /// Runs both sweeps once and closes whatever the session sweep invalidated.
  @discardableResult
  public func sweepOnce() async -> Int {
    sweepCount += 1
    await pairing?.sweepExpired()
    guard let sessions else { return 0 }
    let invalidated = await sessions.sweepInvalidSessions()
    for invalidation in invalidated {
      await closeSession(
        invalidation.identity,
        invalidation.reason.closeReason(in: .authenticatedSession)
      )
    }
    return invalidated.count
  }
}
