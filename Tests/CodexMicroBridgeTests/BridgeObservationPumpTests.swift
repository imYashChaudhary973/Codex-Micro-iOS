import CodexAppServer
import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import MacBridgeCore
import XCTest

@testable import CodexMicroBridge

/// The pump is what makes observation live rather than merely implemented,
/// and the scheduler runs the sweeps Steps 2.5 and 2.6 deliberately left for
/// the assembly.
final class BridgeObservationPumpTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

  // MARK: - Draining the journal

  func testAnAttributedChangeWakesTheSubscribedDevice() async throws {
    let world = try await World()
    try await world.subscribe()
    await world.journal.append(threadID: "thread-a")

    let woken = await world.pump.drain()

    XCTAssertEqual(woken, [deviceID])
    let delivered = await world.pump.deliveredChangeCount
    XCTAssertEqual(delivered, 1)
  }

  /// Attribution must be resolved before the broker is told, or the first
  /// change to a thread would be silently dropped.
  func testTheFirstChangeToAThreadIsNotDropped() async throws {
    let world = try await World()
    try await world.subscribe()
    // Nothing has attributed thread-a yet; the pump must do it itself.
    XCTAssertNil(world.table.projectID(forThreadID: "thread-a"))
    await world.journal.append(threadID: "thread-a")

    let woken = await world.pump.drain()

    XCTAssertEqual(woken, [deviceID])
    XCTAssertNotNil(world.table.projectID(forThreadID: "thread-a"))
  }

  func testAThreadOutsideEveryProjectWakesNobody() async throws {
    let world = try await World()
    try await world.subscribe()
    await world.journal.append(threadID: "thread-elsewhere")

    let woken = await world.pump.drain()

    XCTAssertEqual(woken, [])
    XCTAssertNil(world.table.projectID(forThreadID: "thread-elsewhere"))
  }

  func testTheCursorAdvancesSoAChangeIsDeliveredOnce() async throws {
    let world = try await World()
    try await world.subscribe()
    await world.journal.append(threadID: "thread-a")

    _ = await world.pump.drain()
    _ = await world.pump.drain()

    let delivered = await world.pump.deliveredChangeCount
    XCTAssertEqual(delivered, 1)
    let cursor = await world.pump.currentCursor()
    XCTAssertEqual(cursor, 1)
  }

  func testEveryPendingChangeIsDrainedInOneCall() async throws {
    let world = try await World()
    try await world.subscribe()
    for _ in 0..<5 { await world.journal.append(threadID: "thread-a") }

    _ = await world.pump.drain()

    let delivered = await world.pump.deliveredChangeCount
    XCTAssertEqual(delivered, 5)
    let cursor = await world.pump.currentCursor()
    XCTAssertEqual(cursor, 5)
  }

  /// A retention gap must not be papered over: the pump jumps its cursor and
  /// records the gap, and the devices' own cursor rules turn it into a forced
  /// filtered snapshot.
  func testARetentionGapIsRecordedRatherThanInvented() async throws {
    let world = try await World()
    try await world.subscribe()
    await world.journal.forceSnapshotRequired(latestSequence: 42)

    let woken = await world.pump.drain()

    XCTAssertEqual(woken, [])
    let gaps = await world.pump.retentionGapCount
    XCTAssertEqual(gaps, 1)
    let cursor = await world.pump.currentCursor()
    XCTAssertEqual(cursor, 42)
    let delivered = await world.pump.deliveredChangeCount
    XCTAssertEqual(delivered, 0)
  }

  func testAFailedReplayDeliversNothingAndKeepsTheCursor() async throws {
    let world = try await World()
    try await world.subscribe()
    await world.journal.failReplays(true)

    let woken = await world.pump.drain()

    XCTAssertEqual(woken, [])
    let cursor = await world.pump.currentCursor()
    XCTAssertEqual(cursor, 0, "a cursor the journal cannot serve is not advanced")
  }

  func testAnUnsubscribedDeviceIsNotWoken() async throws {
    let world = try await World()
    await world.journal.append(threadID: "thread-a")

    let woken = await world.pump.drain()

    XCTAssertEqual(woken, [])
  }

  // MARK: - Driving from the update stream

  func testTheStreamDrivesTheDrain() async throws {
    let world = try await World()
    try await world.subscribe()
    await world.journal.append(threadID: "thread-a")
    let pair = AsyncStream<BridgeUpdate>.makeStream()

    await world.pump.start(updates: pair.stream)
    pair.continuation.yield(.stateChanged(latestSequence: 1))
    pair.continuation.finish()
    try await waitUntil { await world.pump.deliveredChangeCount == 1 }

    let delivered = await world.pump.deliveredChangeCount
    XCTAssertEqual(delivered, 1)
    await world.pump.stop()
  }

  func testARecoveryUpdateDoesNotDrain() async throws {
    let world = try await World()
    try await world.subscribe()
    await world.journal.append(threadID: "thread-a")
    let pair = AsyncStream<BridgeUpdate>.makeStream()

    await world.pump.start(updates: pair.stream)
    pair.continuation.yield(.recovery(.rebuilt(threadIDs: [], droppedThreadIDs: [])))
    pair.continuation.finish()
    try? await Task.sleep(for: .milliseconds(60))

    let delivered = await world.pump.deliveredChangeCount
    XCTAssertEqual(delivered, 0, "only a state change drains the journal")
    await world.pump.stop()
  }

  // MARK: - The sweep scheduler

  func testSweepingWithNoCoordinatorsIsSafe() async throws {
    let scheduler = BridgeSweepScheduler(pairing: nil, sessions: nil, closeSession: { _, _ in })

    let closed = await scheduler.sweepOnce()

    XCTAssertEqual(closed, 0)
    let sweeps = await scheduler.sweepCount
    XCTAssertEqual(sweeps, 1)
  }

  func testTheSweepClosesEverySessionItInvalidated() async throws {
    let authority = InMemorySessionAuthority()
    let coordinator = try SessionCoordinator(
      hostID: UUID(),
      hostTLSSPKIFingerprint: Data(repeating: 0x77, count: 32),
      authority: authority,
      signer: RefusingSweepSigner(),
      store: InMemoryAuthenticatedSessionStore()
    )
    let recorder = SweepCloseRecorder()
    let scheduler = BridgeSweepScheduler(
      pairing: nil,
      sessions: coordinator,
      closeSession: { identity, reason in
        await recorder.record(identity: identity, reason: reason)
      }
    )

    // No sessions exist, so the sweep has nothing to close but still runs.
    let closed = await scheduler.sweepOnce()

    XCTAssertEqual(closed, 0)
    let recorded = await recorder.closed
    XCTAssertEqual(recorded.count, 0)
  }

  func testStartingTheSchedulerTwiceRunsOneLoop() async throws {
    let scheduler = BridgeSweepScheduler(
      pairing: nil, sessions: nil, interval: .milliseconds(20), closeSession: { _, _ in })

    await scheduler.start()
    await scheduler.start()
    try await waitUntil { await scheduler.sweepCount >= 2 }
    await scheduler.stop()
    let afterStop = await scheduler.sweepCount
    try? await Task.sleep(for: .milliseconds(80))

    let settled = await scheduler.sweepCount
    XCTAssertEqual(settled, afterStop, "stopping must end the loop")
  }

  // MARK: - Fixtures

  private func waitUntil(
    _ condition: @Sendable () async -> Bool,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async throws {
    for _ in 0..<200 {
      if await condition() { return }
      try? await Task.sleep(for: .milliseconds(5))
    }
    XCTFail("condition never became true", file: file, line: line)
  }

  private struct World {
    let pump: BridgeObservationPump
    let broker: DeviceObservationBroker
    let journal = FakeJournal()
    let table = ThreadProjectTable()
    let authority: DeviceGrantAuthority
    private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

    init() async throws {
      authority = DeviceGrantAuthority(
        storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
      let registry = BridgeProjectRegistry(rootPaths: ["/Users/example/app"])
      let projects = await registry.allProjects()
      let project = try XCTUnwrap(projects.first)
      _ = try await authority.addGrant(
        deviceID: deviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        permittedProjectIDs: [project.projectID]
      )
      broker = DeviceObservationBroker(
        scopes: authority,
        snapshots: PumpSnapshotSource(),
        attribution: table,
        journalEpoch: try SystemJournalEpochMint().mintJournalEpoch()
      )
      let journal = self.journal
      let attribution = BridgeThreadAttributionResolver(
        registry: registry,
        table: table,
        readThread: { threadID in
          .object([
            "id": .string(threadID),
            "cwd": .string(
              threadID == "thread-a" ? "/Users/example/app/src" : "/Users/example/elsewhere"),
          ])
        }
      )
      pump = BridgeObservationPump(
        broker: broker,
        attribution: attribution,
        replay: { cursor in try await journal.replay(after: cursor) }
      )
    }

    func subscribe() async throws {
      _ = try await broker.subscribe(
        deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)
    }
  }
}

/// Deterministic journal with a forced retention gap and replay failure.
actor FakeJournal {
  private var events: [SequencedJournalEvent<BridgeDomainEvent>] = []
  private var next: UInt64 = 1
  private var snapshotRequiredAt: UInt64?
  private var replaysFail = false

  func append(threadID: String) {
    events.append(
      SequencedJournalEvent(
        sequence: next, createdAt: Date(timeIntervalSince1970: 1_000_000),
        event: .threadUpdated(threadID: threadID)))
    next += 1
  }

  func forceSnapshotRequired(latestSequence: UInt64) { snapshotRequiredAt = latestSequence }
  func failReplays(_ value: Bool) { replaysFail = value }

  func replay(after cursor: UInt64) throws -> JournalReplay<BridgeDomainEvent> {
    if replaysFail { throw EventJournalError.sequenceExhausted }
    if let snapshotRequiredAt { return .snapshotRequired(latestSequence: snapshotRequiredAt) }
    return .events(events.filter { $0.sequence > cursor })
  }
}

private struct PumpSnapshotSource: ObservationSnapshotProviding {
  func currentObservationSnapshot() async -> CompanionStateSnapshot {
    CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000_000), latestSequence: 0, threads: [])
  }
}

private struct RefusingSweepSigner: SessionStatementSigner {
  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    throw SessionClosedReason.deviceSignatureUnavailable
  }
}

/// Records every session the sweep asked to close.
actor SweepCloseRecorder {
  private(set) var closed: [(identity: AuthenticatedSessionIdentity, reason: SecureCloseReason)] =
    []

  func record(identity: AuthenticatedSessionIdentity, reason: SecureCloseReason) {
    closed.append((identity, reason))
  }
}
