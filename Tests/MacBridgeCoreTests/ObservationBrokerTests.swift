import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Deterministic scope source. Every mutator models an authorization change
/// that has already committed in the real authority.
final class FakeObservationScopeSource: ObservationScopeProviding, @unchecked Sendable {
  private let lock = NSLock()
  private var results: [UUID: ObservationScopeResult] = [:]
  private var isUnavailable = false

  func observationScope(deviceID: UUID) throws -> ObservationScopeResult {
    lock.lock()
    defer { lock.unlock() }
    if isUnavailable { throw DeviceGrantAuthorityError.authorityUnavailable }
    return results[deviceID] ?? .notObservable
  }

  func set(_ result: ObservationScopeResult, for deviceID: UUID) {
    lock.lock()
    defer { lock.unlock() }
    results[deviceID] = result
  }

  func takeOffline() {
    lock.lock()
    defer { lock.unlock() }
    isUnavailable = true
  }
}

/// Deterministic unfiltered snapshot source.
final class FakeObservationSnapshotSource: ObservationSnapshotProviding, @unchecked Sendable {
  private let lock = NSLock()
  private var threads: [CompanionThreadState] = []
  private(set) var readCount = 0

  func currentObservationSnapshot() -> CompanionStateSnapshot {
    lock.lock()
    defer { lock.unlock() }
    readCount += 1
    return CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000),
      latestSequence: 9_999,
      threads: threads
    )
  }

  func setThreads(_ identifiers: [String]) {
    lock.lock()
    defer { lock.unlock() }
    threads = identifiers.sorted().map {
      CompanionThreadState(
        threadID: $0, status: .active, activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil)
    }
  }
}

final class ObservationBrokerTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
  private let subscriptionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!

  // MARK: - First delivery

  func testFreshSubscriptionReceivesAFilteredSnapshot() async throws {
    let world = try World(projects: ["project-a"])
    world.snapshots.setThreads(["thread-a", "thread-secret"])
    world.attribute("thread-a", "project-a")
    world.attribute("thread-secret", "project-secret")

    let batch = try await world.broker.subscribe(
      deviceID: deviceID, subscriptionID: subscriptionID, resumeCursor: nil)

    guard case .snapshot(let payload, let cursor) = batch else {
      return XCTFail("expected a snapshot")
    }
    XCTAssertEqual(payload.threads.map(\.threadID), ["thread-a"])
    XCTAssertEqual(cursor.deviceID, deviceID)
    XCTAssertEqual(cursor.sequence, 0)
    XCTAssertEqual(cursor.journalEpoch, world.epoch)
  }

  func testDeviceWithoutObservableGrantIsDeniedAndLeavesNoState() async throws {
    let world = try World(projects: ["project-a"])
    world.scopes.set(.notObservable, for: deviceID)

    await assertThrowsErrorAsync(
      try await world.broker.subscribe(
        deviceID: deviceID, subscriptionID: subscriptionID, resumeCursor: nil)
    ) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .notObservable)
    }
    let subscription = await world.broker.subscription(deviceID: deviceID)
    XCTAssertNil(subscription)
  }

  func testUnavailableAuthorityDeniesDisclosure() async throws {
    let world = try World(projects: ["project-a"])
    world.scopes.takeOffline()

    await assertThrowsErrorAsync(
      try await world.broker.subscribe(
        deviceID: deviceID, subscriptionID: subscriptionID, resumeCursor: nil)
    ) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .authorityUnavailable)
    }
  }

  // MARK: - Event flow

  func testAuthorizedChangesDeliverAsEventsAndUnauthorizedOnesDoNot() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    world.attribute("thread-secret", "project-secret")
    _ = try await world.subscribeFresh()

    let firstWake = await world.broker.recordThreadChange(threadID: "thread-a")
    let secondWake = await world.broker.recordThreadChange(threadID: "thread-secret")
    let thirdWake = await world.broker.recordThreadChange(threadID: "thread-a")

    XCTAssertEqual(firstWake, [deviceID])
    XCTAssertEqual(secondWake, [])
    XCTAssertEqual(thirdWake, [deviceID])

    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    guard case .events(let payload, let cursor) = batch else {
      return XCTFail("expected events")
    }
    XCTAssertEqual(payload.events.map(\.sequence), [1, 2])
    XCTAssertEqual(payload.events.map(\.threadID), ["thread-a", "thread-a"])
    XCTAssertEqual(cursor.sequence, 2)
  }

  func testUnattributedChangeIsInvisible() async throws {
    let world = try World(projects: ["project-a"])
    _ = try await world.subscribeFresh()

    let woken = await world.broker.recordThreadChange(threadID: "thread-unattributed")

    XCTAssertEqual(woken, [])
    let batch = try await world.broker.nextBatch(deviceID: deviceID)
    XCTAssertNil(batch)
  }

  func testCaughtUpSubscriptionProducesNothing() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    await world.broker.recordThreadChange(threadID: "thread-a")
    _ = try await world.broker.nextBatch(deviceID: deviceID)

    let next = try await world.broker.nextBatch(deviceID: deviceID)

    XCTAssertNil(next)
  }

  func testTwoDevicesSeeOnlyTheirOwnProjects() async throws {
    let world = try World(projects: ["project-a"])
    world.scopes.set(
      .scoped(try world.scope(deviceID: otherDeviceID, projects: ["project-b"])),
      for: otherDeviceID)
    world.attribute("thread-a", "project-a")
    world.attribute("thread-b", "project-b")
    _ = try await world.subscribeFresh()
    _ = try await world.broker.subscribe(
      deviceID: otherDeviceID, subscriptionID: UUID(), resumeCursor: nil)

    let firstWoken = await world.broker.recordThreadChange(threadID: "thread-a")
    let secondWoken = await world.broker.recordThreadChange(threadID: "thread-b")
    XCTAssertEqual(firstWoken, [deviceID])
    XCTAssertEqual(secondWoken, [otherDeviceID])

    let first = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    let second = try await unwrapAsync(await world.broker.nextBatch(deviceID: otherDeviceID))
    guard case .events(let firstPayload, _) = first,
      case .events(let secondPayload, _) = second
    else { return XCTFail("expected events") }
    XCTAssertEqual(firstPayload.events.map(\.threadID), ["thread-a"])
    XCTAssertEqual(firstPayload.events.map(\.sequence), [1])
    XCTAssertEqual(secondPayload.events.map(\.threadID), ["thread-b"])
    XCTAssertEqual(secondPayload.events.map(\.sequence), [1])
  }

  // MARK: - Acknowledgement

  func testAcknowledgementAdvancesTheWatermark() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    await world.broker.recordThreadChange(threadID: "thread-a")
    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))

    try await world.broker.acknowledge(
      deviceID: deviceID, subscriptionID: subscriptionID, cursor: batch.cursor)

    let subscription = try await unwrapAsync(
      await world.broker.subscription(deviceID: deviceID))
    XCTAssertEqual(subscription.acknowledgedSequence, 1)
    XCTAssertEqual(subscription.deliveredSequence, 1)
  }

  func testAcknowledgementCannotMoveBackwardsOrClaimUndeliveredData() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    for _ in 1...3 { await world.broker.recordThreadChange(threadID: "thread-a") }
    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    try await world.broker.acknowledge(
      deviceID: deviceID, subscriptionID: subscriptionID, cursor: batch.cursor)

    let backwards = try await world.cursor(sequence: 1)
    await assertThrowsErrorAsync(
      try await world.broker.acknowledge(
        deviceID: deviceID, subscriptionID: subscriptionID, cursor: backwards)
    ) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .acknowledgementOutOfOrder)
    }

    await world.broker.recordThreadChange(threadID: "thread-a")
    let undelivered = try await world.cursor(sequence: 4)
    await assertThrowsErrorAsync(
      try await world.broker.acknowledge(
        deviceID: deviceID, subscriptionID: subscriptionID, cursor: undelivered)
    ) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .acknowledgementOutOfOrder)
    }
  }

  func testAcknowledgementForAForeignDeviceFailsClosed() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    await world.broker.recordThreadChange(threadID: "thread-a")
    _ = try await world.broker.nextBatch(deviceID: deviceID)

    let foreign = ReplayCursorEnvelope(
      deviceID: otherDeviceID, grantRevision: 1, authorizedViewEpoch: 1,
      journalEpoch: world.epoch, sequence: 1)

    await assertThrowsErrorAsync(
      try await world.broker.acknowledge(
        deviceID: deviceID, subscriptionID: subscriptionID, cursor: foreign)
    ) { error in
      XCTAssertEqual(
        error as? ObservationSubscriptionError, .cursorRejected(.deviceMismatch))
    }
  }

  func testAcknowledgementForAnUnknownSubscriptionFailsClosed() async throws {
    let world = try World(projects: ["project-a"])
    _ = try await world.subscribeFresh()

    await assertThrowsErrorAsync(
      try await world.broker.acknowledge(
        deviceID: deviceID, subscriptionID: UUID(), cursor: try await world.cursor(sequence: 0))
    ) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .unknownSubscription)
    }
  }

  // MARK: - Reconnect

  func testCurrentCursorResumesWithoutASnapshot() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    for _ in 1...3 { await world.broker.recordThreadChange(threadID: "thread-a") }
    let resume = try await world.cursor(sequence: 1)

    let batch = try await world.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: resume)

    guard case .events(let payload, let cursor) = batch else {
      return XCTFail("expected replayed events")
    }
    XCTAssertEqual(payload.events.map(\.sequence), [2, 3])
    XCTAssertEqual(cursor.sequence, 3)
    XCTAssertEqual(world.snapshots.readCount, 1)
  }

  func testForeignJournalEpochResynchronizesBySnapshot() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    await world.broker.recordThreadChange(threadID: "thread-a")
    let foreignEpoch = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 1, authorizedViewEpoch: 1,
      journalEpoch: try JournalEpoch(rawBytes: Data(repeating: 0xAB, count: 16)), sequence: 1)

    let batch = try await world.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: foreignEpoch)

    guard case .snapshot(_, let cursor) = batch else { return XCTFail("expected a snapshot") }
    XCTAssertEqual(cursor.journalEpoch, world.epoch)
    XCTAssertEqual(cursor.sequence, 1)
  }

  func testAheadCursorFailsClosedOnResume() async throws {
    let world = try World(projects: ["project-a"])
    _ = try await world.subscribeFresh()
    let ahead = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 1, authorizedViewEpoch: 1,
      journalEpoch: world.epoch, sequence: 99)

    await assertThrowsErrorAsync(
      try await world.broker.subscribe(
        deviceID: deviceID, subscriptionID: UUID(), resumeCursor: ahead)
    ) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .cursorRejected(.sequenceAhead))
    }
  }

  // MARK: - Bounded queue and slow consumer

  func testBackPressureStopsDeliveryUntilTheDeviceAcknowledges() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    let total = Int(ObservationLimits.maxUnacknowledgedEvents) + 20
    for _ in 1...total { await world.broker.recordThreadChange(threadID: "thread-a") }

    var delivered: UInt64 = 0
    while let batch = try await world.broker.nextBatch(deviceID: deviceID) {
      guard case .events(let payload, _) = batch else { return XCTFail("expected events") }
      delivered = payload.events.last?.sequence ?? delivered
    }

    XCTAssertEqual(delivered, ObservationLimits.maxUnacknowledgedEvents)
    let stalled = await world.broker.subscription(deviceID: deviceID)
    XCTAssertEqual(stalled?.deliveredSequence, ObservationLimits.maxUnacknowledgedEvents)

    try await world.broker.acknowledge(
      deviceID: deviceID, subscriptionID: subscriptionID,
      cursor: try await world.cursor(sequence: ObservationLimits.maxUnacknowledgedEvents))
    let resumed = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    guard case .events(let payload, _) = resumed else { return XCTFail("expected events") }
    XCTAssertEqual(payload.events.first?.sequence, ObservationLimits.maxUnacknowledgedEvents + 1)
  }

  func testSlowConsumerFallsBackToASnapshotInsteadOfAPartialHistory() async throws {
    let world = try World(projects: ["project-a"], retainedEventCapacity: 4)
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    for _ in 1...3 { await world.broker.recordThreadChange(threadID: "thread-a") }
    _ = try await world.broker.nextBatch(deviceID: deviceID)
    try await world.broker.acknowledge(
      deviceID: deviceID, subscriptionID: subscriptionID,
      cursor: try await world.cursor(sequence: 1))

    // The device stops acknowledging while the retention ring rolls past it.
    for _ in 1...8 { await world.broker.recordThreadChange(threadID: "thread-a") }

    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    guard case .snapshot(_, let cursor) = batch else {
      return XCTFail("expected the snapshot fallback")
    }
    XCTAssertEqual(cursor.sequence, 11)
  }

  func testBatchesNeverExceedTheWireBound() async throws {
    let world = try World(projects: ["project-a"], retainedEventCapacity: 4_096)
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    for _ in 1...100 { await world.broker.recordThreadChange(threadID: "thread-a") }

    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))

    guard case .events(let payload, _) = batch else { return XCTFail("expected events") }
    XCTAssertEqual(payload.events.count, SecureObservationLimits.maxEventBatchCount)
  }

  // MARK: - Authorization changes

  func testScopeReductionForcesASnapshotAndPurgesQueuedData() async throws {
    let world = try World(projects: ["project-a", "project-b"])
    world.attribute("thread-a", "project-a")
    world.attribute("thread-b", "project-b")
    _ = try await world.subscribeFresh()
    await world.broker.recordThreadChange(threadID: "thread-a")
    await world.broker.recordThreadChange(threadID: "thread-b")
    let staleCursor = try await world.cursor(sequence: 2)

    // The Mac committed a scope reduction: revision and view epoch advanced.
    world.scopes.set(
      .scoped(
        try world.scope(deviceID: deviceID, projects: ["project-a"], revision: 2, viewEpoch: 2)),
      for: deviceID)

    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    guard case .snapshot(let payload, let cursor) = batch else {
      return XCTFail("expected a forced snapshot")
    }
    XCTAssertEqual(payload.threads.map(\.threadID), [])
    XCTAssertEqual(cursor.sequence, 0)
    XCTAssertEqual(cursor.grantRevision, 2)
    XCTAssertEqual(cursor.authorizedViewEpoch, 2)

    // A cursor minted under the previous boundary resynchronizes: it never
    // advances the watermark, and it schedules another filtered snapshot.
    try await world.broker.acknowledge(
      deviceID: deviceID, subscriptionID: subscriptionID, cursor: staleCursor)
    let subscription = try await unwrapAsync(
      await world.broker.subscription(deviceID: deviceID))
    XCTAssertTrue(subscription.needsSnapshot)
    XCTAssertEqual(subscription.acknowledgedSequence, 0)
  }

  func testRevocationBetweenOperationsDeniesAndDropsEveryTrace() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    await world.broker.recordThreadChange(threadID: "thread-a")

    world.scopes.set(.notObservable, for: deviceID)

    await assertThrowsErrorAsync(try await world.broker.nextBatch(deviceID: deviceID)) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .notObservable)
    }
    let subscription = await world.broker.subscription(deviceID: deviceID)
    let view = await world.broker.view(deviceID: deviceID)
    XCTAssertNil(subscription)
    XCTAssertNil(view)
  }

  func testRevokedDeviceIsSkippedByFanOutWithoutAffectingOthers() async throws {
    let world = try World(projects: ["project-a"])
    world.scopes.set(
      .scoped(try world.scope(deviceID: otherDeviceID, projects: ["project-a"])),
      for: otherDeviceID)
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    _ = try await world.broker.subscribe(
      deviceID: otherDeviceID, subscriptionID: UUID(), resumeCursor: nil)

    world.scopes.set(.notObservable, for: deviceID)
    let woken = await world.broker.recordThreadChange(threadID: "thread-a")

    XCTAssertEqual(woken, [otherDeviceID])
  }

  func testPurgeRemovesSubscriptionAndRetainedHistory() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    await world.broker.recordThreadChange(threadID: "thread-a")

    await world.broker.purge(deviceID: deviceID)

    let subscription = await world.broker.subscription(deviceID: deviceID)
    let view = await world.broker.view(deviceID: deviceID)
    XCTAssertNil(subscription)
    XCTAssertNil(view)
  }

  func testUnsubscribeKeepsRetainedHistoryForReconnect() async throws {
    let world = try World(projects: ["project-a"])
    world.attribute("thread-a", "project-a")
    _ = try await world.subscribeFresh()
    for _ in 1...2 { await world.broker.recordThreadChange(threadID: "thread-a") }

    await world.broker.unsubscribe(deviceID: deviceID)
    let batch = try await world.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(),
      resumeCursor: try await world.cursor(sequence: 1))

    guard case .events(let payload, _) = batch else { return XCTFail("expected replay") }
    XCTAssertEqual(payload.events.map(\.sequence), [2])
  }

  // MARK: - Fixtures

  private struct World {
    let broker: DeviceObservationBroker
    let scopes = FakeObservationScopeSource()
    let snapshots = FakeObservationSnapshotSource()
    let table = ThreadProjectTable()
    let epoch: JournalEpoch
    private let deviceID: UUID
    private let subscriptionID: UUID

    init(
      projects: Set<String>,
      retainedEventCapacity: Int = DeviceAuthorizedView.defaultRetainedEventCapacity
    ) throws {
      deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
      subscriptionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
      epoch = try JournalEpoch(rawBytes: Data(repeating: 0x11, count: 16))
      broker = DeviceObservationBroker(
        scopes: scopes,
        snapshots: snapshots,
        attribution: table,
        journalEpoch: epoch,
        retainedEventCapacity: retainedEventCapacity
      )
      scopes.set(.scoped(try scope(deviceID: deviceID, projects: projects)), for: deviceID)
    }

    func attribute(_ threadID: String, _ projectID: String) {
      table.attribute(threadID: threadID, projectID: projectID)
    }

    func subscribeFresh() async throws -> AuthorizedObservationBatch {
      try await broker.subscribe(
        deviceID: deviceID, subscriptionID: subscriptionID, resumeCursor: nil)
    }

    func cursor(sequence: UInt64) async throws -> ReplayCursorEnvelope {
      let stored = await broker.view(deviceID: deviceID)
      let view = try XCTUnwrap(stored)
      return view.cursor(at: sequence, journalEpoch: epoch)
    }

    func scope(
      deviceID: UUID,
      projects: Set<String>,
      revision: UInt64 = 1,
      viewEpoch: UInt64 = 1
    ) throws -> AuthorizedViewScope {
      AuthorizedViewScope(
        grant: try AuthoritativeDeviceGrant(
          deviceID: deviceID,
          devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
          createdAtEpochSeconds: 100,
          lastSeenAtEpochSeconds: 100,
          capabilities: [.view],
          permittedProjectIDs: projects,
          actionProfileCeiling: .observe,
          grantRevision: revision,
          authorizedViewEpoch: viewEpoch,
          expiresAtEpochSeconds: nil,
          tombstone: nil
        )
      )
    }
  }
}

// MARK: - Async assertion helpers

func assertThrowsErrorAsync<T>(
  _ expression: @autoclosure () async throws -> T,
  file: StaticString = #filePath,
  line: UInt = #line,
  _ handler: (any Error) -> Void = { _ in }
) async {
  do {
    _ = try await expression()
    XCTFail("expected an error", file: file, line: line)
  } catch {
    handler(error)
  }
}

func unwrapAsync<T>(
  _ expression: @autoclosure () async throws -> T?,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws -> T {
  let value = try await expression()
  return try XCTUnwrap(value, file: file, line: line)
}
