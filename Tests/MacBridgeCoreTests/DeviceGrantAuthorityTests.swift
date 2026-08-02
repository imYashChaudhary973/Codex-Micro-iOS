import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

final class DeviceGrantAuthorityTests: XCTestCase {
  private let deviceID = UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!

  func testFreshInstallExplicitEmptyIsAvailable() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

    let availability = await authority.availability()
    XCTAssertEqual(availability, .available)
    let snapshot = try await authority.macAdministrationSnapshot()
    XCTAssertEqual(snapshot.hostGeneration, 1)
    XCTAssertEqual(snapshot.authoritySequence, 0)
    XCTAssertEqual(snapshot.grants, [])
  }

  func testMissingCorruptDuplicateAndStoreFailureLoadUnavailable() async {
    let cases: [(DeviceGrantAuthorityError, Data?)] = [
      (.authorityMissing, nil),
      (.duplicateAuthorityItem, nil),
      (.storageUnavailable, nil),
      (.corruptAuthority, Data([0x00])),
    ]
    for (failure, corruptBlob) in cases {
      let store = InMemoryGrantAuthorityStore()
      if let corruptBlob {
        store.setBlob(corruptBlob)
      } else {
        store.failLoads(with: failure)
      }
      let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

      let availability = await authority.availability()
      XCTAssertEqual(availability, .unavailable(failure))
      await assertAuthorityError(.authorityUnavailable) {
        _ = try await authority.currentHostGeneration()
      }
    }
  }

  func testAddGrantUsesSecureDefaultsPersistsAndReopens() async throws {
    let store = InMemoryGrantAuthorityStore()
    let clock = TestGrantClock(epochSeconds: 1_000)
    let authority = DeviceGrantAuthority(storage: store, clock: clock.reader)

    let added = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )

    XCTAssertEqual(added.createdAtEpochSeconds, 1_000)
    XCTAssertEqual(added.lastSeenAtEpochSeconds, 1_000)
    XCTAssertEqual(added.capabilities, [.view])
    XCTAssertEqual(added.permittedProjectIDs, [])
    XCTAssertEqual(added.actionProfileCeiling, .observe)
    XCTAssertEqual(added.grantRevision, 1)
    XCTAssertEqual(added.authorizedViewEpoch, 1)
    XCTAssertNil(added.tombstone)
    XCTAssertEqual(store.writeLog.count, 1)

    let reopened = DeviceGrantAuthority(storage: store, clock: clock.reader)
    let reopenedGrant = try await reopened.authoritativeGrant(deviceID: deviceID)
    let reopenedSnapshot = try await reopened.macAdministrationSnapshot()
    XCTAssertEqual(reopenedGrant, added)
    XCTAssertEqual(reopenedSnapshot.authoritySequence, 1)
  }

  func testAddRejectsExpiredInputWithoutWriting() async {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

    await assertAuthorityError(.invalidGrant) {
      _ = try await authority.addGrant(
        deviceID: self.deviceID,
        devicePublicKey: self.validPublicKey(0x11),
        expiresAtEpochSeconds: 100
      )
    }
    XCTAssertEqual(store.writeLog.count, 0)
    let availability = await authority.availability()
    XCTAssertEqual(availability, .available)
  }

  func testRevokePersistsPermanentTombstoneAndBumpsRevisionAndViewEpoch() async throws {
    let store = InMemoryGrantAuthorityStore()
    let clock = TestGrantClock(epochSeconds: 100)
    let authority = DeviceGrantAuthority(storage: store, clock: clock.reader)
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    clock.advance(to: 120)

    let revoked = try await authority.revoke(deviceID: deviceID)

    XCTAssertEqual(revoked.grantRevision, 2)
    XCTAssertEqual(revoked.authorizedViewEpoch, 2)
    XCTAssertTrue(revoked.isRevoked)
    XCTAssertEqual(revoked.revokedAtEpochSeconds, 120)
    XCTAssertNil(revoked.expiredAtEpochSeconds)
    XCTAssertEqual(
      revoked.tombstone,
      DeviceGrantTombstone(kind: .revoked, tombstonedAtEpochSeconds: 120)
    )
    await assertAuthorityError(.deviceRevoked) {
      _ = try await authority.authoritativeGrant(deviceID: self.deviceID)
    }

    let reopened = DeviceGrantAuthority(storage: store, clock: clock.reader)
    await assertAuthorityError(.deviceRevoked) {
      _ = try await reopened.authoritativeGrant(deviceID: self.deviceID)
    }
    let persisted = try await reopened.macAdministrationSnapshot().grants.first
    XCTAssertEqual(persisted, revoked)
  }

  func testTombstonedDeviceIDCanNeverBeRegranted() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    _ = try await authority.revoke(deviceID: deviceID)

    await assertAuthorityError(.deviceRevoked) {
      _ = try await authority.addGrant(
        deviceID: self.deviceID,
        devicePublicKey: self.validPublicKey(0x22)
      )
    }
  }

  func testPassiveExpiryDeniesAtBoundaryThenExplicitExpirePersistsTombstone() async throws {
    let store = InMemoryGrantAuthorityStore()
    let clock = TestGrantClock(epochSeconds: 100)
    let authority = DeviceGrantAuthority(storage: store, clock: clock.reader)
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11),
      expiresAtEpochSeconds: 110
    )
    let activeGrant = try await authority.authoritativeGrant(deviceID: deviceID)
    XCTAssertNotNil(activeGrant)

    clock.advance(to: 110)
    await assertAuthorityError(.deviceExpired) {
      _ = try await authority.authoritativeGrant(deviceID: self.deviceID)
    }
    let passiveRecord = try await authority.macAdministrationSnapshot().grants[0]
    XCTAssertNil(passiveRecord.tombstone)
    XCTAssertEqual(passiveRecord.grantRevision, 1)
    XCTAssertEqual(store.writeLog.count, 1)

    let expired = try await authority.expire(deviceID: deviceID)
    XCTAssertEqual(expired.grantRevision, 2)
    XCTAssertEqual(expired.authorizedViewEpoch, 2)
    XCTAssertFalse(expired.isRevoked)
    XCTAssertNil(expired.revokedAtEpochSeconds)
    XCTAssertEqual(expired.expiredAtEpochSeconds, 110)
    XCTAssertEqual(expired.tombstone?.kind, .expired)
    XCTAssertEqual(expired.tombstone?.tombstonedAtEpochSeconds, 110)
    XCTAssertEqual(store.writeLog.count, 2)
  }

  func testExplicitExpireBeforeDeadlineUsesDistinctClosedReason() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11),
      expiresAtEpochSeconds: 200
    )

    let expired = try await authority.expire(deviceID: deviceID)
    XCTAssertEqual(expired.tombstone?.kind, .expired)
    await assertAuthorityError(.deviceExpired) {
      _ = try await authority.authoritativeGrant(deviceID: self.deviceID)
    }
  }

  func testReduceScopeRequiresStrictSubsetAndBumpsRevisionAndViewEpoch() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11),
      permittedProjectIDs: ["a", "b"]
    )

    let reduced = try await authority.reduceScope(
      deviceID: deviceID,
      permittedProjectIDs: ["a"]
    )
    XCTAssertEqual(reduced.permittedProjectIDs, ["a"])
    XCTAssertEqual(reduced.grantRevision, 2)
    XCTAssertEqual(reduced.authorizedViewEpoch, 2)

    await assertAuthorityError(.invalidGrant) {
      _ = try await authority.reduceScope(
        deviceID: self.deviceID,
        permittedProjectIDs: ["a", "c"]
      )
    }
    await assertAuthorityError(.invalidGrant) {
      _ = try await authority.reduceScope(
        deviceID: self.deviceID,
        permittedProjectIDs: ["a"]
      )
    }
    XCTAssertEqual(store.writeLog.count, 2)
  }

  func testCapabilityAmendmentBumpsRevisionAndOnlyViewMembershipBumpsViewEpoch() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11),
      capabilities: [.view, .interrupt]
    )

    let actionsChanged = try await authority.amendCapabilities(
      deviceID: deviceID,
      capabilities: [.view, .runAgent],
      actionProfileCeiling: .runReadOnly
    )
    XCTAssertEqual(actionsChanged.grantRevision, 2)
    XCTAssertEqual(actionsChanged.authorizedViewEpoch, 1)

    let viewRemoved = try await authority.amendCapabilities(
      deviceID: deviceID,
      capabilities: [.runAgent],
      actionProfileCeiling: .runReadOnly
    )
    XCTAssertEqual(viewRemoved.grantRevision, 3)
    XCTAssertEqual(viewRemoved.authorizedViewEpoch, 2)
  }

  func testTouchLastSeenPersistsWithoutChangingAuthorizationVersions() async throws {
    let store = InMemoryGrantAuthorityStore()
    let clock = TestGrantClock(epochSeconds: 100)
    let authority = DeviceGrantAuthority(storage: store, clock: clock.reader)
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    clock.advance(to: 150)

    let touched = try await authority.touchLastSeen(deviceID: deviceID)

    XCTAssertEqual(touched.lastSeenAtEpochSeconds, 150)
    XCTAssertEqual(touched.grantRevision, 1)
    XCTAssertEqual(touched.authorizedViewEpoch, 1)
    let snapshot = try await authority.macAdministrationSnapshot()
    XCTAssertEqual(snapshot.authoritySequence, 2)
  }

  func testClockRollbackCannotBlockLastSeenOrRevocationPersistence() async throws {
    let clock = TestGrantClock(epochSeconds: 100)
    let authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(),
      clock: clock.reader
    )
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    clock.advance(to: 50)

    let touched = try await authority.touchLastSeen(deviceID: deviceID)
    let revoked = try await authority.revoke(deviceID: deviceID)

    XCTAssertEqual(touched.lastSeenAtEpochSeconds, 100)
    XCTAssertEqual(revoked.tombstone?.tombstonedAtEpochSeconds, 100)
  }

  func testPolicyBridgeReusesCapabilityPolicyWithoutDuplicatingLogic() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11),
      capabilities: [.runAgent],
      permittedProjectIDs: ["project-1"],
      actionProfileCeiling: .runReadOnly
    )
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(timeIntervalSince1970: 100),
      body: .sendPrompt(threadID: "thread-1", prompt: "continue", attachmentIDs: [])
    )

    let grant = try await authority.effectiveGrant(deviceID: deviceID)
    let handleGrant = try await authority.deviceHandle(for: deviceID).effectiveGrant()
    XCTAssertEqual(grant, handleGrant)
    XCTAssertEqual(
      CapabilityPolicy.authorize(
        command: command,
        grant: grant,
        resolvedProjectID: "project-1",
        hostProfile: .runWorkspace,
        now: Date(timeIntervalSince1970: 100)
      ),
      .allowed(effectiveProfile: .runReadOnly)
    )
  }

  func testStorageFailureLatchesClosedAndPersistBeforeVisibleKeepsPriorState() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    let original = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    store.failReplacements(with: .storageUnavailable)

    await assertAuthorityError(.storageUnavailable) {
      _ = try await authority.revoke(deviceID: self.deviceID)
    }
    let failedAvailability = await authority.availability()
    XCTAssertEqual(failedAvailability, .unavailable(.storageUnavailable))
    await assertAuthorityError(.authorityUnavailable) {
      _ = try await authority.touchLastSeen(deviceID: self.deviceID)
    }

    store.failReplacements(with: nil)
    try await authority.reloadFromStore()
    let reloaded = try await authority.authoritativeGrant(deviceID: deviceID)
    let recoveredAvailability = await authority.availability()
    XCTAssertEqual(reloaded, original)
    XCTAssertEqual(recoveredAvailability, .available)
  }

  func testSpecificPersistenceFailureIsPreservedThenSubsequentCallsUseUnavailable() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    store.failReplacements(with: .duplicateAuthorityItem)

    await assertAuthorityError(.duplicateAuthorityItem) {
      _ = try await authority.revoke(deviceID: self.deviceID)
    }
    let availability = await authority.availability()
    XCTAssertEqual(availability, .unavailable(.duplicateAuthorityItem))
    await assertAuthorityError(.authorityUnavailable) {
      _ = try await authority.revoke(deviceID: self.deviceID)
    }
  }

  func testOversizedMutationLeavesPriorAuthorityAvailable() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    let projects = Set(
      (0..<GrantAuthorityLimits.maxProjectCount).map { index in
        String(format: "%0124d-%03d", 0, index)
      })
    let firstID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    let secondID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    _ = try await authority.addGrant(
      deviceID: firstID,
      devicePublicKey: validPublicKey(0x11),
      permittedProjectIDs: projects
    )

    await assertAuthorityError(.authorityOversized) {
      _ = try await authority.addGrant(
        deviceID: secondID,
        devicePublicKey: self.validPublicKey(0x22),
        permittedProjectIDs: projects
      )
    }
    let availability = await authority.availability()
    let firstGrant = try await authority.authoritativeGrant(deviceID: firstID)
    XCTAssertEqual(availability, .available)
    XCTAssertNotNil(firstGrant)
    await assertAuthorityError(.deviceUnknown) {
      _ = try await authority.authoritativeGrant(deviceID: secondID)
    }
    XCTAssertEqual(store.writeLog.count, 1)
  }

  func testReloadRejectsSequenceRollbackAndMissingPersistedAuthority() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    let oldBlob = try XCTUnwrap(store.currentBlob)
    _ = try await authority.touchLastSeen(deviceID: deviceID)
    store.setBlob(oldBlob)

    await assertAuthorityError(.rollbackDetected) {
      try await authority.reloadFromStore()
    }
    let availability = await authority.availability()
    XCTAssertEqual(availability, .unavailable(.rollbackDetected))

    let missingStore = InMemoryGrantAuthorityStore()
    let missingAuthority = DeviceGrantAuthority(storage: missingStore, clock: { 100 })
    _ = try await missingAuthority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    missingStore.clear()
    await assertAuthorityError(.authorityMissing) {
      try await missingAuthority.reloadFromStore()
    }
  }

  func testReloadRejectsDifferentStateAtSameSequence() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    let state = try GrantAuthorityBlobCodec.decode(XCTUnwrap(store.currentBlob))
    let substituted = GrantAuthorityState(
      hostGeneration: state.hostGeneration + 1,
      authoritySequence: state.authoritySequence,
      grants: state.grants
    )
    store.setBlob(try GrantAuthorityBlobCodec.encode(substituted))

    await assertAuthorityError(.rollbackDetected) {
      try await authority.reloadFromStore()
    }
  }

  func testHostGenerationAdvancesOnlyThroughGlobalInvalidation() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    let initialGeneration = try await authority.currentHostGeneration()
    let advancedGeneration = try await authority.advanceHostGeneration()
    let grant = try await authority.authoritativeGrant(deviceID: deviceID)
    XCTAssertEqual(initialGeneration, 1)
    XCTAssertEqual(advancedGeneration, 2)
    XCTAssertEqual(grant.grantRevision, 1)
  }

  func testDeviceScopedHandleCannotAffectAnotherDevice() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    let otherID = UUID(uuidString: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")!
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11)
    )
    _ = try await authority.addGrant(
      deviceID: otherID,
      devicePublicKey: validPublicKey(0x22)
    )
    let deviceHandle = authority.deviceHandle(for: deviceID)
    let otherBefore = try await authority.authoritativeGrant(deviceID: otherID)

    let deviceBefore = try await deviceHandle.authoritativeGrant()
    XCTAssertEqual(deviceBefore.deviceID, deviceID)
    _ = try await deviceHandle.touchLastSeen()
    let otherAfterTouch = try await authority.authoritativeGrant(deviceID: otherID)
    XCTAssertEqual(otherAfterTouch, otherBefore)

    _ = try await authority.revoke(deviceID: otherID)
    let deviceAfterRevokingOther = try await deviceHandle.authoritativeGrant()
    XCTAssertEqual(deviceAfterRevokingOther.deviceID, deviceID)
    await assertAuthorityError(.deviceRevoked) {
      _ = try await authority.deviceHandle(for: otherID).authoritativeGrant()
    }
  }

  func testAuthoritySequenceOverflowFailsClosed() async throws {
    let store = try storeWithState(
      GrantAuthorityState(
        hostGeneration: 1,
        authoritySequence: .max,
        grants: [deviceID: try fixtureGrant()]
      ))
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

    await assertCounterOverflowAndClosed(authority) {
      _ = try await authority.touchLastSeen(deviceID: self.deviceID)
    }
  }

  func testGrantRevisionOverflowFailsClosed() async throws {
    let grant = try fixtureGrant(grantRevision: .max)
    let store = try storeWithState(
      GrantAuthorityState(hostGeneration: 1, authoritySequence: 1, grants: [deviceID: grant]))
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

    await assertCounterOverflowAndClosed(authority) {
      _ = try await authority.amendCapabilities(
        deviceID: self.deviceID,
        capabilities: [.view, .interrupt],
        actionProfileCeiling: .observe
      )
    }
  }

  func testAuthorizedViewEpochOverflowFailsClosed() async throws {
    let grant = try fixtureGrant(
      projects: ["a", "b"],
      authorizedViewEpoch: .max
    )
    let store = try storeWithState(
      GrantAuthorityState(hostGeneration: 1, authoritySequence: 1, grants: [deviceID: grant]))
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

    await assertCounterOverflowAndClosed(authority) {
      _ = try await authority.reduceScope(
        deviceID: self.deviceID,
        permittedProjectIDs: ["a"]
      )
    }
  }

  func testHostGenerationOverflowFailsClosed() async throws {
    let store = try storeWithState(
      GrantAuthorityState(
        hostGeneration: .max,
        authoritySequence: 1,
        grants: [deviceID: try fixtureGrant()]
      ))
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })

    await assertCounterOverflowAndClosed(authority) {
      _ = try await authority.advanceHostGeneration()
    }
  }

  // MARK: - Helpers

  private func fixtureGrant(
    projects: Set<String> = [],
    grantRevision: UInt64 = 1,
    authorizedViewEpoch: UInt64 = 1
  ) throws -> AuthoritativeDeviceGrant {
    try AuthoritativeDeviceGrant(
      deviceID: deviceID,
      devicePublicKey: validPublicKey(0x11),
      createdAtEpochSeconds: 100,
      lastSeenAtEpochSeconds: 100,
      capabilities: [.view],
      permittedProjectIDs: projects,
      actionProfileCeiling: .observe,
      grantRevision: grantRevision,
      authorizedViewEpoch: authorizedViewEpoch,
      expiresAtEpochSeconds: nil,
      tombstone: nil
    )
  }

  private func storeWithState(_ state: GrantAuthorityState) throws -> InMemoryGrantAuthorityStore {
    let store = InMemoryGrantAuthorityStore()
    store.setBlob(try GrantAuthorityBlobCodec.encode(state))
    return store
  }

  private func validPublicKey(_ firstScalarByte: UInt8) -> Data {
    let scalar = Data((0..<32).map { firstScalarByte + UInt8($0) })
    return try! P256.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
  }

  private func assertCounterOverflowAndClosed(
    _ authority: DeviceGrantAuthority,
    operation: () async throws -> Void
  ) async {
    await assertAuthorityError(.counterOverflow, operation: operation)
    let availability = await authority.availability()
    XCTAssertEqual(availability, .unavailable(.counterOverflow))
    await assertAuthorityError(.authorityUnavailable) {
      _ = try await authority.currentHostGeneration()
    }
  }

  private func assertAuthorityError(
    _ expected: DeviceGrantAuthorityError,
    operation: () async throws -> Void
  ) async {
    do {
      try await operation()
      XCTFail("Expected \(expected)")
    } catch {
      XCTAssertEqual(error as? DeviceGrantAuthorityError, expected)
    }
  }
}
