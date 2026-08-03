import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Step 2.8 linearizable authorization changes: commit, purge, then report
/// what the transport must close. Every test runs against the real
/// ``DeviceGrantAuthority``, the real broker, and the real read-cursor store.
final class AuthorizationChangeCoordinatorTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!

  // MARK: - Terminal changes

  func testRevocationCommitsPurgesAndReportsAClose() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()

    let outcome = try await world.coordinator.revoke(deviceID: deviceID)

    XCTAssertEqual(outcome.kind, .revoked)
    XCTAssertEqual(outcome.connectionAction, .close(.deviceRevoked))
    XCTAssertEqual(outcome.grantRevision, 2)
    XCTAssertEqual(outcome.authorizedViewEpoch, 2)
    XCTAssertTrue(outcome.observation.hadSubscription)
    XCTAssertFalse(outcome.observation.retainsObservation)
    XCTAssertEqual(outcome.observation.discardedEvents, 2)
    XCTAssertEqual(outcome.discardedReadCursors, 1)

    let subscription = await world.broker.subscription(deviceID: deviceID)
    let view = await world.broker.view(deviceID: deviceID)
    let remaining = await world.readCursors.storedThreadCount(deviceID: deviceID)
    XCTAssertNil(subscription)
    XCTAssertNil(view)
    XCTAssertEqual(remaining, 0)
  }

  func testExpiryCommitsTheTombstoneBeforeReportingAClose() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()

    let outcome = try await world.coordinator.expire(deviceID: deviceID)

    XCTAssertEqual(outcome.kind, .expired)
    XCTAssertEqual(outcome.connectionAction, .close(.grantExpired))
    let scope = try await world.authority.observationScope(deviceID: deviceID)
    XCTAssertEqual(scope, .notObservable)
  }

  func testTerminalChangesLeaveOtherDevicesUntouched() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()
    try await world.addSecondDevice()

    _ = try await world.coordinator.revoke(deviceID: deviceID)

    let otherSubscription = await world.broker.subscription(deviceID: otherDeviceID)
    let otherCursors = await world.readCursors.storedThreadCount(deviceID: otherDeviceID)
    XCTAssertNotNil(otherSubscription)
    XCTAssertEqual(otherCursors, 1)
    let otherScope = try await world.authority.observationScope(deviceID: otherDeviceID)
    guard case .scoped = otherScope else { return XCTFail("expected the other device to remain") }
  }

  // MARK: - Retaining changes

  func testScopeReductionPurgesUnauthorizedDataAndAsksForReauthentication()
    async throws
  {
    let world = try await World(projects: ["project-a", "project-b"])
    try await world.openSessionWithData()
    _ = try await world.readCursors.advance(deviceID: deviceID, threadID: "thread-b", to: 3)

    let outcome = try await world.coordinator.reduceScope(
      deviceID: deviceID, permittedProjectIDs: ["project-a"])

    XCTAssertEqual(outcome.kind, .scopeReduced)
    XCTAssertEqual(outcome.connectionAction, .reauthenticate)
    XCTAssertEqual(outcome.authorizedViewEpoch, 2)
    XCTAssertTrue(outcome.observation.retainsObservation)
    XCTAssertEqual(outcome.discardedReadCursors, 1)

    // The retained history was dropped and the namespace restarted, so the
    // next delivery is a fresh filtered snapshot at sequence 0.
    let view = try await unwrapAsync(await world.broker.view(deviceID: deviceID))
    XCTAssertEqual(view.latestSequence, 0)
    XCTAssertEqual(view.events(after: 0), [])
    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    guard case .snapshot(_, let cursor) = batch else { return XCTFail("expected a snapshot") }
    XCTAssertEqual(cursor.authorizedViewEpoch, 2)
    XCTAssertEqual(cursor.sequence, 0)
  }

  func testLosingViewCapabilityEndsObservationAndClosesTheConnection() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()

    let outcome = try await world.coordinator.amendCapabilities(
      deviceID: deviceID, capabilities: [.interrupt], actionProfileCeiling: .observe)

    XCTAssertEqual(outcome.kind, .capabilitiesAmended)
    XCTAssertEqual(outcome.connectionAction, .close(.authorizationChanged))
    XCTAssertFalse(outcome.observation.retainsObservation)
    XCTAssertEqual(outcome.authorizedViewEpoch, 2)
    let view = await world.broker.view(deviceID: deviceID)
    XCTAssertNil(view)
  }

  func testCapabilityChangeThatKeepsViewOnlyRequiresReauthentication() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()

    let outcome = try await world.coordinator.amendCapabilities(
      deviceID: deviceID, capabilities: [.view, .interrupt], actionProfileCeiling: .observe)

    XCTAssertEqual(outcome.connectionAction, .reauthenticate)
    XCTAssertEqual(outcome.grantRevision, 2)
    XCTAssertEqual(outcome.authorizedViewEpoch, 1)
    XCTAssertTrue(outcome.observation.retainsObservation)
    // The disclosure boundary did not move, so authorized history survives.
    let view = try await unwrapAsync(await world.broker.view(deviceID: deviceID))
    XCTAssertEqual(view.latestSequence, 2)
  }

  // MARK: - Host-wide invalidation

  func testHostGenerationAdvanceInvalidatesEveryDevice() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()
    try await world.addSecondDevice()

    let outcomes = try await world.coordinator.invalidateAllDevices()

    XCTAssertEqual(outcomes.count, 2)
    XCTAssertEqual(Set(outcomes.map(\.kind)), [.hostGenerationAdvanced])
    XCTAssertTrue(outcomes.allSatisfy { $0.connectionAction == .reauthenticate })
    let generation = try await world.authority.currentHostGeneration()
    XCTAssertEqual(generation, 2)
  }

  // MARK: - Failure behaviour

  func testAFailedCommitPurgesNothingAndClosesNothing() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()
    world.storage.failReplacements(with: .storageUnavailable)

    await assertThrowsErrorAsync(try await world.coordinator.revoke(deviceID: deviceID)) { error in
      XCTAssertEqual(
        error as? AuthorizationChangeError, .commitFailed(.storageUnavailable))
    }

    let cursors = await world.readCursors.storedThreadCount(deviceID: deviceID)
    XCTAssertEqual(cursors, 1)
  }

  func testRevokingAnAlreadyRevokedDeviceFailsClosed() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()
    _ = try await world.coordinator.revoke(deviceID: deviceID)

    await assertThrowsErrorAsync(try await world.coordinator.revoke(deviceID: deviceID)) { error in
      XCTAssertEqual(error as? AuthorizationChangeError, .commitFailed(.deviceRevoked))
    }
  }

  func testRevokingAnUnknownDeviceFailsClosed() async throws {
    let world = try await World(projects: ["project-a"])

    await assertThrowsErrorAsync(try await world.coordinator.revoke(deviceID: otherDeviceID)) {
      error in
      XCTAssertEqual(error as? AuthorizationChangeError, .commitFailed(.deviceUnknown))
    }
  }

  // MARK: - Ordering

  /// Every operation started **after** the commit returns is denied. This is
  /// the half of invariant 11 that is a hard guarantee: an operation that
  /// began earlier may legitimately complete under the prior authorization,
  /// but none may begin under it afterwards.
  func testEveryOperationStartedAfterTheCommitIsDenied() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()
    let broker = world.broker
    let readCursors = world.readCursors
    let target = deviceID

    _ = try await world.coordinator.revoke(deviceID: target)

    let denials = await withTaskGroup(of: Bool.self) { group -> Int in
      for _ in 0..<32 {
        group.addTask { (try? await broker.nextBatch(deviceID: target)) == nil }
        group.addTask {
          (try? await readCursors.advance(deviceID: target, threadID: "thread-a", to: 99)) == nil
        }
      }
      var denied = 0
      for await wasDenied in group where wasDenied { denied += 1 }
      return denied
    }

    XCTAssertEqual(denials, 64)
  }

  /// Racing a revocation against live polling must never leave partial state:
  /// whatever the interleaving, the device ends fully purged and denied.
  func testRacingPollsAndRevocationEndFullyPurged() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()
    let broker = world.broker
    let coordinator = world.coordinator
    let target = deviceID

    await withTaskGroup(of: Void.self) { group in
      group.addTask { _ = try? await coordinator.revoke(deviceID: target) }
      for _ in 0..<32 {
        group.addTask { _ = try? await broker.nextBatch(deviceID: target) }
      }
    }

    await assertThrowsErrorAsync(try await broker.nextBatch(deviceID: target)) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .notObservable)
    }
    let subscription = await broker.subscription(deviceID: target)
    let view = await broker.view(deviceID: target)
    let cursors = await world.readCursors.storedThreadCount(deviceID: target)
    XCTAssertNil(subscription)
    XCTAssertNil(view)
    XCTAssertEqual(cursors, 0)
  }

  func testOutcomeCarriesThePublishedAuthoritySequence() async throws {
    let world = try await World(projects: ["project-a"])
    try await world.openSessionWithData()
    let before = try await world.authority.macAdministrationSnapshot().authoritySequence

    let outcome = try await world.coordinator.revoke(deviceID: deviceID)

    XCTAssertGreaterThan(outcome.authoritySequence, before)
    let after = try await world.authority.macAdministrationSnapshot().authoritySequence
    XCTAssertEqual(outcome.authoritySequence, after)
  }

  // MARK: - Fixtures

  private struct World {
    let authority: DeviceGrantAuthority
    let broker: DeviceObservationBroker
    let readCursors: DeviceReadCursorStore
    let coordinator: AuthorizationChangeCoordinator
    let snapshots = FakeObservationSnapshotSource()
    let table = ThreadProjectTable()
    let storage = InMemoryGrantAuthorityStore()
    private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
    private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!

    init(projects: Set<String>) async throws {
      authority = DeviceGrantAuthority(storage: storage, clock: { 100 })
      _ = try await authority.addGrant(
        deviceID: deviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        permittedProjectIDs: projects
      )
      table.attribute(threadID: "thread-a", projectID: "project-a")
      table.attribute(threadID: "thread-b", projectID: "project-b")
      snapshots.setThreads(["thread-a", "thread-b"])
      broker = DeviceObservationBroker(
        scopes: authority,
        snapshots: snapshots,
        attribution: table,
        journalEpoch: try SystemJournalEpochMint().mintJournalEpoch()
      )
      readCursors = try DeviceReadCursorStore(
        storage: InMemoryReadCursorStorage(),
        scopes: authority,
        attribution: table,
        clock: { 1_000 }
      )
      coordinator = AuthorizationChangeCoordinator(
        authority: authority, broker: broker, readCursors: readCursors)
    }

    /// Subscribes the device, gives it two retained events and one read
    /// position, so a purge has something to discard.
    func openSessionWithData() async throws {
      _ = try await broker.subscribe(
        deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)
      await broker.recordThreadChange(threadID: "thread-a")
      await broker.recordThreadChange(threadID: "thread-a")
      _ = try await readCursors.advance(deviceID: deviceID, threadID: "thread-a", to: 2)
    }

    func addSecondDevice() async throws {
      _ = try await authority.addGrant(
        deviceID: otherDeviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        permittedProjectIDs: ["project-a"]
      )
      _ = try await broker.subscribe(
        deviceID: otherDeviceID, subscriptionID: UUID(), resumeCursor: nil)
      _ = try await readCursors.advance(deviceID: otherDeviceID, threadID: "thread-a", to: 1)
    }
  }
}
