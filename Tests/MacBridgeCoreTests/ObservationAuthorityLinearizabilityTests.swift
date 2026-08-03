import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// The observation path reads the real ``DeviceGrantAuthority``, and it must
/// keep reading it — a committed authorization change has to be in force for
/// the very next disclosure, with no cached scope in between.
final class ObservationAuthorityLinearizabilityTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

  // MARK: - Authority adapter

  func testAuthorityMapsLivenessOntoObservationScope() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID, devicePublicKey: publicKey(), permittedProjectIDs: ["project-a"])

    let live = try await authority.observationScope(deviceID: deviceID)
    guard case .scoped(let scope) = live else { return XCTFail("expected a scope") }
    XCTAssertEqual(scope.permittedProjectIDs, ["project-a"])
    XCTAssertEqual(scope.grantRevision, 1)

    let unknown = try await authority.observationScope(deviceID: UUID())
    XCTAssertEqual(unknown, .notObservable)

    _ = try await authority.revoke(deviceID: deviceID)
    let revoked = try await authority.observationScope(deviceID: deviceID)
    XCTAssertEqual(revoked, .notObservable)
  }

  func testExpiredGrantIsNotObservable() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID, devicePublicKey: publicKey(), expiresAtEpochSeconds: 150)
    _ = try await authority.expire(deviceID: deviceID)

    let scope = try await authority.observationScope(deviceID: deviceID)

    XCTAssertEqual(scope, .notObservable)
  }

  func testGrantWithoutViewCapabilityIsNotObservable() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID, devicePublicKey: publicKey(), capabilities: [.interrupt],
      permittedProjectIDs: ["project-a"])

    let scope = try await authority.observationScope(deviceID: deviceID)

    XCTAssertEqual(scope, .notObservable)
  }

  func testUnavailableAuthorityPropagatesRatherThanDenyingQuietly() async {
    let store = InMemoryGrantAuthorityStore()
    store.failLoads(with: .storageUnavailable)
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

    await assertThrowsErrorAsync(try await authority.observationScope(deviceID: deviceID)) {
      error in
      XCTAssertEqual(error as? DeviceGrantAuthorityError, .authorityUnavailable)
    }
  }

  // MARK: - Linearizable revocation against live traffic

  func testRevocationCommittedBeforeDisclosureDeniesTheVeryNextRead() async throws {
    let world = try await World(projects: ["project-a"])
    _ = try await world.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)
    await world.broker.recordThreadChange(threadID: "thread-a")

    _ = try await world.authority.revoke(deviceID: deviceID)

    await assertThrowsErrorAsync(try await world.broker.nextBatch(deviceID: deviceID)) {
      error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .notObservable)
    }
    let view = await world.broker.view(deviceID: deviceID)
    XCTAssertNil(view)
  }

  func testConcurrentChangesAndRevocationNeverDiscloseAfterTheCommit() async throws {
    let world = try await World(projects: ["project-a"])
    _ = try await world.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)
    let broker = world.broker
    let authority = world.authority
    let target = deviceID

    await withTaskGroup(of: Void.self) { group in
      for _ in 0..<64 {
        group.addTask { await broker.recordThreadChange(threadID: "thread-a") }
      }
      group.addTask { _ = try? await authority.revoke(deviceID: target) }
    }

    // Whatever interleaving occurred, the committed revocation is in force
    // for every later read and nothing survives for the revoked device.
    await assertThrowsErrorAsync(try await broker.nextBatch(deviceID: deviceID)) { error in
      XCTAssertEqual(error as? ObservationSubscriptionError, .notObservable)
    }
    let subscription = await broker.subscription(deviceID: deviceID)
    let view = await broker.view(deviceID: deviceID)
    XCTAssertNil(subscription)
    XCTAssertNil(view)
  }

  func testScopeReductionCommittedInTheAuthorityForcesAFilteredSnapshot() async throws {
    let world = try await World(projects: ["project-a", "project-b"])
    _ = try await world.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)
    world.table.attribute(threadID: "thread-b", projectID: "project-b")
    world.snapshots.setThreads(["thread-a", "thread-b"])
    await world.broker.recordThreadChange(threadID: "thread-b")

    _ = try await world.authority.reduceScope(
      deviceID: deviceID, permittedProjectIDs: ["project-a"])

    let batch = try await unwrapAsync(await world.broker.nextBatch(deviceID: deviceID))
    guard case .snapshot(let payload, let cursor) = batch else {
      return XCTFail("expected a forced filtered snapshot")
    }
    XCTAssertEqual(payload.threads.map(\.threadID), ["thread-a"])
    XCTAssertEqual(cursor.grantRevision, 2)
    XCTAssertEqual(cursor.authorizedViewEpoch, 2)
    XCTAssertEqual(cursor.sequence, 0)
  }

  func testRevocationSurvivesAuthorityReopen() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID, devicePublicKey: publicKey(), permittedProjectIDs: ["project-a"])
    _ = try await authority.revoke(deviceID: deviceID)

    let reopened = DeviceGrantAuthority(storage: store, clock: { 100 })
    let scope = try await reopened.observationScope(deviceID: deviceID)

    XCTAssertEqual(scope, .notObservable)
  }

  func testFreshProcessJournalEpochMakesAPreviousProcessCursorForeign() async throws {
    let first = try await World(projects: ["project-a"])
    _ = try await first.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)
    await first.broker.recordThreadChange(threadID: "thread-a")
    let view = try await unwrapAsync(await first.broker.view(deviceID: deviceID))
    let previousCursor = view.cursor(at: 1, journalEpoch: first.epoch)

    // A restarted bridge mints a new epoch over the same authority.
    let restarted = try await World(projects: ["project-a"], authority: first.authority)
    XCTAssertNotEqual(restarted.epoch, first.epoch)

    let batch = try await restarted.broker.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: previousCursor)

    guard case .snapshot(_, let cursor) = batch else {
      return XCTFail("expected a snapshot for a foreign journal epoch")
    }
    XCTAssertEqual(cursor.journalEpoch, restarted.epoch)
    XCTAssertEqual(cursor.sequence, 0)
  }

  // MARK: - Fixtures

  private func publicKey() -> Data {
    P256.Signing.PrivateKey().publicKey.x963Representation
  }

  private struct World {
    let authority: DeviceGrantAuthority
    let broker: DeviceObservationBroker
    let snapshots = FakeObservationSnapshotSource()
    let table = ThreadProjectTable()
    let epoch: JournalEpoch

    init(
      projects: Set<String>,
      authority existing: DeviceGrantAuthority? = nil
    ) async throws {
      let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
      if let existing {
        authority = existing
      } else {
        authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
        _ = try await authority.addGrant(
          deviceID: deviceID,
          devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
          permittedProjectIDs: projects
        )
      }
      epoch = try SystemJournalEpochMint().mintJournalEpoch()
      table.attribute(threadID: "thread-a", projectID: "project-a")
      snapshots.setThreads(["thread-a"])
      broker = DeviceObservationBroker(
        scopes: authority,
        snapshots: snapshots,
        attribution: table,
        journalEpoch: epoch
      )
    }
  }
}
