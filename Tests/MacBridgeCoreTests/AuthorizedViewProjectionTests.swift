import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Step 2.8 per-device authorized-view projection: scope derivation, the
/// private sequence namespace, retention, cursor authority, and filtered
/// snapshots.
final class AuthorizedViewProjectionTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!

  // MARK: - Scope derivation

  func testPairingDefaultGrantPermitsNoProject() throws {
    let scope = AuthorizedViewScope(
      grant: try grant(capabilities: [.view], projects: [])
    )

    XCTAssertTrue(scope.allowsObservation)
    XCTAssertEqual(scope.permittedProjectIDs, [])
    XCTAssertFalse(scope.permits(projectID: "project-a"))
    XCTAssertFalse(scope.permits(projectID: nil))
  }

  func testGrantWithoutViewCapabilityDisclosesNothing() throws {
    let scope = AuthorizedViewScope(
      grant: try grant(capabilities: [.interrupt], projects: ["project-a"])
    )

    XCTAssertFalse(scope.allowsObservation)
    XCTAssertEqual(scope.permittedProjectIDs, [])
    XCTAssertFalse(scope.permits(projectID: "project-a"))
  }

  func testTombstonedGrantDisclosesNothing() throws {
    for kind in DeviceGrantTombstone.Kind.allCases {
      let scope = AuthorizedViewScope(
        grant: try grant(
          capabilities: [.view],
          projects: ["project-a"],
          tombstone: DeviceGrantTombstone(kind: kind, tombstonedAtEpochSeconds: 200)
        )
      )

      XCTAssertFalse(scope.allowsObservation)
      XCTAssertFalse(scope.permits(projectID: "project-a"))
    }
  }

  func testScopeCarriesAuthorityCounters() throws {
    let scope = AuthorizedViewScope(
      grant: try grant(capabilities: [.view], projects: ["project-a"], revision: 9, viewEpoch: 4)
    )

    XCTAssertEqual(scope.deviceID, deviceID)
    XCTAssertEqual(scope.grantRevision, 9)
    XCTAssertEqual(scope.authorizedViewEpoch, 4)
  }

  // MARK: - Private sequence namespace

  func testUnauthorizedProjectActivityDoesNotAdvanceTheDeviceVisibleSequence() throws {
    var view = DeviceAuthorizedView(scope: try scope(projects: ["project-a"]))

    let first = try view.admit(threadID: "thread-1", projectID: "project-a")
    XCTAssertNil(try view.admit(threadID: "thread-9", projectID: "project-secret"))
    XCTAssertNil(try view.admit(threadID: "thread-8", projectID: "project-secret"))
    let second = try view.admit(threadID: "thread-2", projectID: "project-a")
    XCTAssertNil(try view.admit(threadID: "thread-7", projectID: "project-secret"))
    let third = try view.admit(threadID: "thread-1", projectID: "project-a")

    XCTAssertEqual([first?.sequence, second?.sequence, third?.sequence], [1, 2, 3])
    XCTAssertEqual(view.latestSequence, 3)
    XCTAssertEqual(view.events(after: 0).map(\.sequence), [1, 2, 3])
  }

  func testUnattributedThreadIsInvisibleEvenWithBroadScope() throws {
    var view = DeviceAuthorizedView(scope: try scope(projects: ["project-a", "project-b"]))

    XCTAssertNil(try view.admit(threadID: "thread-1", projectID: nil))

    XCTAssertEqual(view.latestSequence, 0)
    XCTAssertEqual(view.events(after: 0), [])
  }

  func testDeviceWithoutViewCapabilitySeesNoEvent() throws {
    var view = DeviceAuthorizedView(
      scope: AuthorizedViewScope(
        grant: try grant(capabilities: [.interrupt], projects: ["project-a"])
      )
    )

    XCTAssertNil(try view.admit(threadID: "thread-1", projectID: "project-a"))
    XCTAssertEqual(view.latestSequence, 0)
  }

  func testAdmittedEventCarriesKindThreadAndProject() throws {
    var view = DeviceAuthorizedView(scope: try scope(projects: ["project-a"]))

    let event = try XCTUnwrap(try view.admit(threadID: "thread-1", projectID: "project-a"))

    XCTAssertEqual(event.kind, .threadUpdated)
    XCTAssertEqual(event.threadID, "thread-1")
    XCTAssertEqual(event.projectID, "project-a")
  }

  /// Project IDs are already bounded by the grant authority, but thread IDs
  /// come from Codex and are bounded only here.
  func testOversizedThreadIdentifierFailsClosedWithoutConsumingASequence() throws {
    var view = DeviceAuthorizedView(scope: try scope(projects: ["project-a"]))

    XCTAssertThrowsError(
      try view.admit(threadID: String(repeating: "t", count: 200), projectID: "project-a")
    ) { error in
      XCTAssertEqual(error as? ObservationProjectionError, .projectionOversized)
    }
    XCTAssertEqual(view.latestSequence, 0)
    XCTAssertEqual(view.events(after: 0), [])
  }

  func testGrantAuthorityAndWireAgreeOnTheProjectIdentifierBound() {
    XCTAssertEqual(
      GrantAuthorityLimits.maxProjectIDBytes, SecureObservationLimits.maxProjectIDBytes)
  }

  func testSequenceExhaustionFailsClosedInsteadOfWrapping() throws {
    var view = DeviceAuthorizedView(
      scope: try scope(projects: ["project-a"]), latestSequence: UInt64.max - 2)

    let last = try XCTUnwrap(try view.admit(threadID: "thread-1", projectID: "project-a"))
    XCTAssertEqual(last.sequence, UInt64.max - 1)

    XCTAssertThrowsError(try view.admit(threadID: "thread-1", projectID: "project-a")) { error in
      XCTAssertEqual(error as? ObservationProjectionError, .sequenceExhausted)
    }
    XCTAssertEqual(view.latestSequence, UInt64.max - 1)
  }

  // MARK: - Retention

  func testRetentionRingBoundsHistoryAndMovesTheReplayFloor() throws {
    var view = DeviceAuthorizedView(
      scope: try scope(projects: ["project-a"]), retainedEventCapacity: 3)

    for index in 1...5 {
      _ = try view.admit(threadID: "thread-\(index)", projectID: "project-a")
    }

    XCTAssertEqual(view.latestSequence, 5)
    XCTAssertEqual(view.events(after: 0).map(\.sequence), [3, 4, 5])
    XCTAssertEqual(view.oldestReplayableSequence, 2)
  }

  func testEmptyViewReplaysOnlyAtItsWatermark() throws {
    let view = DeviceAuthorizedView(scope: try scope(projects: ["project-a"]))

    XCTAssertEqual(view.latestSequence, 0)
    XCTAssertEqual(view.oldestReplayableSequence, 0)
    XCTAssertEqual(view.events(after: 0), [])
  }

  // MARK: - Cursor authority

  func testCurrentCursorReplaysAndOlderCursorsResynchronize() throws {
    let epoch = try journalEpoch(0x11)
    var view = DeviceAuthorizedView(
      scope: try scope(projects: ["project-a"], revision: 7, viewEpoch: 3))
    for index in 1...4 {
      _ = try view.admit(threadID: "thread-\(index)", projectID: "project-a")
    }
    let authority = try view.cursorAuthority(journalEpoch: epoch)

    XCTAssertEqual(
      view.cursor(at: 2, journalEpoch: epoch).evaluate(against: authority),
      .replay(afterSequence: 2)
    )
    XCTAssertEqual(view.events(after: 2).map(\.sequence), [3, 4])

    let staleRevision = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 6, authorizedViewEpoch: 3,
      journalEpoch: epoch, sequence: 2)
    XCTAssertEqual(staleRevision.evaluate(against: authority), .snapshot(.staleGrantRevision))

    let staleView = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 7, authorizedViewEpoch: 2,
      journalEpoch: epoch, sequence: 2)
    XCTAssertEqual(staleView.evaluate(against: authority), .snapshot(.staleAuthorizedViewEpoch))

    let foreignEpoch = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 7, authorizedViewEpoch: 3,
      journalEpoch: try journalEpoch(0x22), sequence: 2)
    XCTAssertEqual(foreignEpoch.evaluate(against: authority), .snapshot(.foreignJournalEpoch))
  }

  func testCrossDeviceAndAheadCursorsFailClosed() throws {
    let epoch = try journalEpoch(0x11)
    var view = DeviceAuthorizedView(
      scope: try scope(projects: ["project-a"], revision: 7, viewEpoch: 3))
    _ = try view.admit(threadID: "thread-1", projectID: "project-a")
    let authority = try view.cursorAuthority(journalEpoch: epoch)

    let foreignDevice = ReplayCursorEnvelope(
      deviceID: otherDeviceID, grantRevision: 7, authorizedViewEpoch: 3,
      journalEpoch: epoch, sequence: 1)
    XCTAssertEqual(foreignDevice.evaluate(against: authority), .reject(.deviceMismatch))

    let aheadSequence = view.cursor(at: 2, journalEpoch: epoch)
    XCTAssertEqual(aheadSequence.evaluate(against: authority), .reject(.sequenceAhead))

    let aheadRevision = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 8, authorizedViewEpoch: 3,
      journalEpoch: epoch, sequence: 1)
    XCTAssertEqual(aheadRevision.evaluate(against: authority), .reject(.grantRevisionAhead))

    let aheadView = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 7, authorizedViewEpoch: 4,
      journalEpoch: epoch, sequence: 1)
    XCTAssertEqual(aheadView.evaluate(against: authority), .reject(.authorizedViewEpochAhead))
  }

  func testRetentionStaleCursorResynchronizesBySnapshot() throws {
    let epoch = try journalEpoch(0x11)
    var view = DeviceAuthorizedView(
      scope: try scope(projects: ["project-a"]), retainedEventCapacity: 2)
    for index in 1...5 {
      _ = try view.admit(threadID: "thread-\(index)", projectID: "project-a")
    }
    let authority = try view.cursorAuthority(journalEpoch: epoch)

    XCTAssertEqual(
      view.cursor(at: 1, journalEpoch: epoch).evaluate(against: authority),
      .snapshot(.retentionExpired)
    )
    XCTAssertEqual(
      view.cursor(at: 3, journalEpoch: epoch).evaluate(against: authority),
      .replay(afterSequence: 3)
    )
  }

  // MARK: - Scope adoption

  func testScopeReductionPurgesHistoryAndRestartsTheNamespace() throws {
    var view = DeviceAuthorizedView(
      scope: try scope(projects: ["project-a", "project-b"], revision: 1, viewEpoch: 1))
    _ = try view.admit(threadID: "thread-a", projectID: "project-a")
    _ = try view.admit(threadID: "thread-b", projectID: "project-b")
    XCTAssertEqual(view.latestSequence, 2)

    view.adopt(scope: try scope(projects: ["project-a"], revision: 2, viewEpoch: 2))

    XCTAssertEqual(view.latestSequence, 0)
    XCTAssertEqual(view.events(after: 0), [])
    XCTAssertNil(try view.admit(threadID: "thread-b", projectID: "project-b"))
    let next = try XCTUnwrap(try view.admit(threadID: "thread-a", projectID: "project-a"))
    XCTAssertEqual(next.sequence, 1)
  }

  func testRevisionOnlyChangeKeepsHistoryButStillForcesASnapshot() throws {
    let epoch = try journalEpoch(0x11)
    var view = DeviceAuthorizedView(
      scope: try scope(projects: ["project-a"], revision: 1, viewEpoch: 1))
    _ = try view.admit(threadID: "thread-a", projectID: "project-a")
    let staleCursor = view.cursor(at: 1, journalEpoch: epoch)

    view.adopt(scope: try scope(projects: ["project-a"], revision: 2, viewEpoch: 1))

    XCTAssertEqual(view.latestSequence, 1)
    XCTAssertEqual(view.events(after: 0).map(\.sequence), [1])
    XCTAssertEqual(
      staleCursor.evaluate(against: try view.cursorAuthority(journalEpoch: epoch)),
      .snapshot(.staleGrantRevision)
    )
  }

  func testAdoptIgnoresAForeignDeviceScope() throws {
    var view = DeviceAuthorizedView(scope: try scope(projects: ["project-a"]))
    _ = try view.admit(threadID: "thread-a", projectID: "project-a")

    view.adopt(
      scope: AuthorizedViewScope(
        grant: try grant(
          deviceID: otherDeviceID, capabilities: [.view], projects: [], revision: 9, viewEpoch: 9)
      )
    )

    XCTAssertEqual(view.scope.deviceID, deviceID)
    XCTAssertEqual(view.latestSequence, 1)
  }

  // MARK: - Filtered snapshots

  func testSnapshotDropsUnauthorizedAndUnattributedThreads() throws {
    let table = ThreadProjectTable()
    table.attribute(threadID: "thread-a", projectID: "project-a")
    table.attribute(threadID: "thread-secret", projectID: "project-secret")
    let snapshot = CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000),
      latestSequence: 99,
      threads: [
        thread("thread-secret"), thread("thread-a"), thread("thread-unattributed"),
      ]
    )

    let filtered = try AuthorizedSnapshotProjection.filter(
      snapshot, scope: try scope(projects: ["project-a"]), attribution: table)

    XCTAssertEqual(filtered.threads.map(\.threadID), ["thread-a"])
    XCTAssertEqual(filtered.threads.first?.projectID, "project-a")
    XCTAssertEqual(filtered.generatedAtEpochSeconds, 1_000)
  }

  func testSnapshotIsSortedAndCarriesNoHostSequence() throws {
    let table = ThreadProjectTable()
    for name in ["c", "a", "b"] {
      table.attribute(threadID: "thread-\(name)", projectID: "project-a")
    }
    let snapshot = CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000),
      latestSequence: 12_345,
      threads: ["thread-c", "thread-a", "thread-b"].map(thread)
    )

    let filtered = try AuthorizedSnapshotProjection.filter(
      snapshot, scope: try scope(projects: ["project-a"]), attribution: table)

    XCTAssertEqual(filtered.threads.map(\.threadID), ["thread-a", "thread-b", "thread-c"])
    let encoded = String(decoding: try JSONEncoder().encode(filtered), as: UTF8.self)
    XCTAssertFalse(encoded.contains("12345"))
    XCTAssertFalse(encoded.contains("latestSequence"))
  }

  func testSnapshotCarriesNoApprovalContent() throws {
    let table = ThreadProjectTable()
    table.attribute(threadID: "thread-a", projectID: "project-a")
    let approval = CompanionPendingApproval(
      requestID: "request-secret",
      threadID: "thread-a",
      turnID: "approval-turn-secret",
      itemID: "item-secret",
      kind: .command,
      availableDecisions: [],
      requestDigest: "digest-secret",
      createdAt: Date(timeIntervalSince1970: 1),
      expiresAt: Date(timeIntervalSince1970: 2),
      status: .pending
    )
    let snapshot = CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000),
      latestSequence: 4,
      threads: [thread("thread-a")],
      pendingApprovals: [approval]
    )

    let filtered = try AuthorizedSnapshotProjection.filter(
      snapshot, scope: try scope(projects: ["project-a"]), attribution: table)

    let encoded = String(decoding: try JSONEncoder().encode(filtered), as: UTF8.self)
    for secret in [
      "request-secret", "digest-secret", "item-secret", "approval-turn-secret", "approval",
    ] {
      XCTAssertFalse(encoded.contains(secret), "leaked \(secret)")
    }
  }

  func testOverlargeSnapshotFailsClosedRatherThanTruncating() throws {
    let table = ThreadProjectTable()
    let count = SecureObservationLimits.maxSnapshotThreadCount + 1
    let identifiers = (0..<count).map { String(format: "thread-%04d", $0) }
    for identifier in identifiers {
      table.attribute(threadID: identifier, projectID: "project-a")
    }
    let snapshot = CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000),
      latestSequence: 1,
      threads: identifiers.map(thread)
    )

    XCTAssertThrowsError(
      try AuthorizedSnapshotProjection.filter(
        snapshot, scope: try scope(projects: ["project-a"]), attribution: table)
    ) { error in
      XCTAssertEqual(error as? ObservationProjectionError, .projectionOversized)
    }
  }

  func testDeniedAttributionDisclosesNothing() throws {
    let snapshot = CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000),
      latestSequence: 1,
      threads: [thread("thread-a")]
    )

    let filtered = try AuthorizedSnapshotProjection.filter(
      snapshot,
      scope: try scope(projects: ["project-a"]),
      attribution: DeniedThreadProjectAttribution()
    )

    XCTAssertEqual(filtered.threads, [])
  }

  // MARK: - Attribution table and journal epoch

  func testAttributionTableRejectsMalformedPairsAndForgets() {
    let table = ThreadProjectTable()

    XCTAssertFalse(table.attribute(threadID: "", projectID: "project-a"))
    XCTAssertFalse(table.attribute(threadID: "thread-a", projectID: ""))
    XCTAssertFalse(table.attribute(threadID: "thread-a", projectID: "project\u{0007}a"))
    XCTAssertFalse(
      table.attribute(threadID: "thread-a", projectID: String(repeating: "p", count: 129)))
    XCTAssertTrue(table.attribute(threadID: "thread-a", projectID: "project-a"))
    XCTAssertNil(table.projectID(forThreadID: "thread-missing"))

    XCTAssertEqual(table.projectID(forThreadID: "thread-a"), "project-a")
    table.forget(threadID: "thread-a")
    XCTAssertNil(table.projectID(forThreadID: "thread-a"))
  }

  func testAttributionTableFiltersMalformedSeedEntries() {
    let table = ThreadProjectTable(attribution: ["thread-a": "project-a", "": "project-b"])

    XCTAssertEqual(table.projectID(forThreadID: "thread-a"), "project-a")
    XCTAssertNil(table.projectID(forThreadID: ""))
  }

  func testJournalEpochIsSixteenFreshBytesPerMint() throws {
    let mint = SystemJournalEpochMint()

    let first = try mint.mintJournalEpoch()
    let second = try mint.mintJournalEpoch()

    XCTAssertEqual(first.rawBytes.count, 16)
    XCTAssertNotEqual(first, second)
  }

  // MARK: - Helpers

  private func thread(_ threadID: String) -> CompanionThreadState {
    CompanionThreadState(
      threadID: threadID,
      status: .active,
      activeTurnID: "turn-1",
      lastTurnID: "turn-1",
      lastTurnStatus: .inProgress
    )
  }

  private func journalEpoch(_ byte: UInt8) throws -> JournalEpoch {
    try JournalEpoch(rawBytes: Data(repeating: byte, count: 16))
  }

  private func scope(
    projects: Set<String>,
    revision: UInt64 = 1,
    viewEpoch: UInt64 = 1
  ) throws -> AuthorizedViewScope {
    AuthorizedViewScope(
      grant: try grant(
        capabilities: [.view], projects: projects, revision: revision, viewEpoch: viewEpoch)
    )
  }

  private func grant(
    deviceID: UUID? = nil,
    capabilities: Set<DeviceCapability>,
    projects: Set<String>,
    revision: UInt64 = 1,
    viewEpoch: UInt64 = 1,
    tombstone: DeviceGrantTombstone? = nil
  ) throws -> AuthoritativeDeviceGrant {
    try AuthoritativeDeviceGrant(
      deviceID: deviceID ?? self.deviceID,
      devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
      createdAtEpochSeconds: 100,
      lastSeenAtEpochSeconds: 100,
      capabilities: capabilities,
      permittedProjectIDs: projects,
      actionProfileCeiling: .observe,
      grantRevision: revision,
      authorizedViewEpoch: viewEpoch,
      expiresAtEpochSeconds: nil,
      tombstone: tombstone
    )
  }
}
