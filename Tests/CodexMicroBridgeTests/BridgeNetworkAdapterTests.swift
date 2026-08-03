import CodexAppServer
import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import MacBridgeCore
import MacBridgeServer
import XCTest

@testable import CodexMicroBridge

/// The adapters that join the three targets Phase 2 deliberately kept apart.
///
/// These tests matter more than their size suggests: this is the one file in
/// the product where `MacBridgeServer`, `MacBridgeCore`, and `CompanionCrypto`
/// meet, so it is the one place the module boundaries could be undone by a
/// careless translation.
final class BridgeNetworkAdapterTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!

  // MARK: - Grant authority → session authority

  func testALiveGrantBecomesALiveSnapshotCarryingTheAuthorityCounters() async throws {
    let world = try await World()

    let snapshot = try await unwrapAsync(
      try await world.sessionAuthority.authoritySnapshot(deviceID: deviceID))

    XCTAssertEqual(snapshot.deviceID, deviceID)
    XCTAssertEqual(snapshot.liveness, .live)
    XCTAssertEqual(snapshot.grantRevision, 1)
    XCTAssertEqual(snapshot.authorizedViewEpoch, 1)
    XCTAssertEqual(snapshot.hostGeneration, 1)
    XCTAssertGreaterThan(snapshot.authorityCommitSequence, 0)
    XCTAssertNil(snapshot.remainingLifetimeSeconds)
  }

  func testAnUnknownDeviceIsNilRatherThanAnError() async throws {
    let world = try await World()

    let snapshot = try await world.sessionAuthority.authoritySnapshot(deviceID: UUID())

    XCTAssertNil(snapshot)
  }

  /// A revoked device must surface its **closed liveness**, not "unknown":
  /// the coordinator denies with the right reason only if it can tell the
  /// difference.
  func testRevokedAndExpiredDevicesKeepTheirDistinctLiveness() async throws {
    for (isRevoke, expected) in [(true, SessionAuthorityLiveness.revoked), (false, .expired)] {
      let world = try await World()
      if isRevoke {
        _ = try await world.authority.revoke(deviceID: deviceID)
      } else {
        _ = try await world.authority.expire(deviceID: deviceID)
      }

      let snapshot = try await unwrapAsync(
        try await world.sessionAuthority.authoritySnapshot(deviceID: deviceID))

      XCTAssertEqual(snapshot.liveness, expected)
      XCTAssertEqual(snapshot.remainingLifetimeSeconds, 0)
    }
  }

  func testAnUnavailableAuthorityThrowsRatherThanReportingAnUnknownDevice() async throws {
    let world = try await World()
    world.storage.failLoads(with: .storageUnavailable)
    try? await world.authority.reloadFromStore()

    await assertThrowsErrorAsync(
      try await world.sessionAuthority.authoritySnapshot(deviceID: deviceID))
  }

  func testRemainingLifetimeIsADurationAndNeverUnderflows() throws {
    let record = try grant(expiresAt: 1_500)

    XCTAssertEqual(
      GrantAuthoritySessionAuthority.remainingLifetime(record, now: 1_000), 500)
    XCTAssertEqual(
      GrantAuthoritySessionAuthority.remainingLifetime(record, now: 1_500), 0)
    XCTAssertEqual(
      GrantAuthoritySessionAuthority.remainingLifetime(record, now: 9_999), 0,
      "a passed expiry reports zero rather than underflowing"
    )
    XCTAssertNil(
      GrantAuthoritySessionAuthority.remainingLifetime(try grant(expiresAt: nil), now: 1_000))
  }

  func testTheSnapshotCarriesAKeyTheCoordinatorCanValidate() async throws {
    let world = try await World()

    let snapshot = try await unwrapAsync(
      try await world.sessionAuthority.authoritySnapshot(deviceID: deviceID))

    // `SessionAuthoritySnapshot.init` rejects a key that is not a valid
    // X9.63 P-256 point, so reaching here proves the stored key survives the
    // crossing intact.
    XCTAssertEqual(snapshot.devicePublicKeyX963.count, 65)
    XCTAssertEqual(snapshot.devicePublicKeyX963.first, 0x04)
  }

  // MARK: - Observation broker → transport

  func testEveryBrokerFailureMapsOntoAClosedTransportRefusal() {
    let cases: [(ObservationSubscriptionError, ListenerObservationRefusal)] = [
      (.notObservable, .notAuthorized),
      (.authorityUnavailable, .authorityUnavailable),
      (.cursorRejected(.deviceMismatch), .cursorRejected),
      (.unknownSubscription, .protocolViolation),
      (.acknowledgementOutOfOrder, .protocolViolation),
      (.projectionFailed(.sequenceExhausted), .protocolViolation),
    ]

    for (failure, expected) in cases {
      XCTAssertEqual(BrokerObservationHandler.refusal(for: failure), expected, "\(failure)")
    }
  }

  func testAnUnexpectedErrorIsRefusedRatherThanPassedThrough() {
    struct Unexpected: Error {}

    XCTAssertEqual(BrokerObservationHandler.refusal(for: Unexpected()), .protocolViolation)
  }

  func testBothBatchShapesCrossUnchanged() throws {
    let cursor = ReplayCursorEnvelope(
      deviceID: deviceID, grantRevision: 1, authorizedViewEpoch: 1,
      journalEpoch: try JournalEpoch(rawBytes: Data(repeating: 0x11, count: 16)), sequence: 3)
    let snapshot = try SecureObservationSnapshot(generatedAtEpochSeconds: 1_000, threads: [])
    let events = try SecureObservationEventBatch(events: [
      try SecureObservationEvent(
        sequence: 3, kind: .threadUpdated, threadID: "thread-a", projectID: "project-a")
    ])

    let snapshotBatch = BrokerObservationHandler.transportBatch(
      .snapshot(snapshot, cursor: cursor))
    let eventBatch = BrokerObservationHandler.transportBatch(.events(events, cursor: cursor))

    XCTAssertEqual(snapshotBatch.payload, .snapshot(snapshot))
    XCTAssertEqual(snapshotBatch.cursor, cursor)
    XCTAssertEqual(eventBatch.payload, .events(events))
    XCTAssertEqual(eventBatch.cursor, cursor)
  }

  func testANonObservableDeviceIsRefusedThroughTheRealBroker() async throws {
    let world = try await World()
    _ = try await world.authority.revoke(deviceID: deviceID)

    await assertThrowsErrorAsync(
      try await world.observationHandler.subscribe(
        deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)
    ) { error in
      XCTAssertEqual(error as? ListenerObservationRefusal, .notAuthorized)
    }
  }

  func testAnAuthorizedSubscriptionCrossesAsAFilteredSnapshot() async throws {
    let world = try await World()

    let batch = try await world.observationHandler.subscribe(
      deviceID: deviceID, subscriptionID: UUID(), resumeCursor: nil)

    guard case .snapshot = batch.payload else { return XCTFail("expected a snapshot") }
    XCTAssertEqual(batch.cursor.deviceID, deviceID)
  }

  // MARK: - Command gateway → transport

  func testEveryGatewayOutcomeMapsOntoAClosedTransportOutcome() async throws {
    let record = try await sampleRecord()
    let cases: [(NetworkCommandOutcome, ListenerCommandOutcome)] = [
      (.completed(record), .completed),
      (.replayed(record), .completed),
      (.outcomeUnknown(record), .outcomeUnknown),
      (.failed(record), .failed),
      (.denied(.capabilityMissing), .denied(.capabilityMissing)),
    ]

    for (outcome, expected) in cases {
      XCTAssertEqual(GatewayCommandHandler.transportOutcome(outcome), expected, "\(outcome)")
    }
  }

  /// Every closed denial reason must survive the crossing exactly, or the
  /// device would be told the wrong thing about why it was refused.
  func testEveryDenialReasonCrossesUnchanged() {
    for reason in SecureCommandDenialReason.allCases {
      XCTAssertEqual(
        GatewayCommandHandler.transportOutcome(.denied(reason)), .denied(reason), "\(reason)")
    }
  }

  func testACommandFromAnUnverifiedSessionIsDeniedThroughTheRealGateway() async throws {
    let world = try await World()
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(timeIntervalSince1970: 1_000_000),
      body: .markThreadRead(threadID: "thread-a", throughSequence: 2)
    )

    // No session was ever registered, so the verifier refuses.
    let outcome = await world.commandHandler.execute(
      command: command, deviceID: deviceID, sessionID: sessionID)

    XCTAssertEqual(outcome, .denied(.revokedDevice))
  }

  // MARK: - Session verifier

  func testAnUnregisteredSessionIsNotCurrent() async throws {
    let world = try await World()

    let isCurrent = await world.sessionVerifier.isCurrentSession(
      deviceID: deviceID, sessionID: sessionID)

    XCTAssertFalse(isCurrent)
  }

  // MARK: - Fixtures

  private func grant(expiresAt: UInt64?) throws -> AuthoritativeDeviceGrant {
    try AuthoritativeDeviceGrant(
      deviceID: deviceID,
      devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
      createdAtEpochSeconds: 100,
      lastSeenAtEpochSeconds: 100,
      capabilities: [.view],
      permittedProjectIDs: ["project-a"],
      actionProfileCeiling: .observe,
      grantRevision: 1,
      authorizedViewEpoch: 1,
      expiresAtEpochSeconds: expiresAt,
      tombstone: nil
    )
  }

  private func sampleRecord() async throws -> CommandLedgerRecord {
    let claim = try await InMemoryCommandLedger().claim(
      deviceID: deviceID,
      commandID: UUID(),
      kind: .markThreadRead,
      semanticDigest: String(repeating: "0", count: 64),
      at: Date(timeIntervalSince1970: 1_000_000)
    )
    guard case .claimed(let record) = claim else { throw ClaimFailed() }
    return record
  }

  private struct ClaimFailed: Error {}

  private struct World {
    let authority: DeviceGrantAuthority
    let storage = InMemoryGrantAuthorityStore()
    let table = ThreadProjectTable()
    let sessionAuthority: GrantAuthoritySessionAuthority
    let sessionVerifier: SessionCoordinatorVerifier
    let observationHandler: BrokerObservationHandler
    let commandHandler: GatewayCommandHandler

    init() async throws {
      let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
      authority = DeviceGrantAuthority(storage: storage, clock: { 1_000_000 })
      _ = try await authority.addGrant(
        deviceID: deviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: [.view, .interrupt],
        permittedProjectIDs: ["project-a"]
      )
      table.attribute(threadID: "thread-a", projectID: "project-a")

      sessionAuthority = GrantAuthoritySessionAuthority(
        authority: authority, clock: { 1_000_000 })
      let coordinator = try SessionCoordinator(
        hostID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
        hostTLSSPKIFingerprint: Data(repeating: 0x77, count: 32),
        authority: sessionAuthority,
        signer: RefusingStatementSigner(),
        store: InMemoryAuthenticatedSessionStore()
      )
      sessionVerifier = SessionCoordinatorVerifier(coordinator: coordinator)

      let broker = DeviceObservationBroker(
        scopes: authority,
        snapshots: EmptyObservationSnapshotSource(),
        attribution: table,
        journalEpoch: try SystemJournalEpochMint().mintJournalEpoch()
      )
      observationHandler = BrokerObservationHandler(broker: broker)

      let readCursors = try DeviceReadCursorStore(
        storage: InMemoryReadCursorStorage(),
        scopes: authority,
        attribution: table,
        clock: { 1_000_000 }
      )
      commandHandler = GatewayCommandHandler(
        gateway: NetworkCommandGateway(
          authority: authority,
          attribution: table,
          ledger: InMemoryCommandLedger(),
          sessions: sessionVerifier,
          runtime: AlwaysReadyRuntime(),
          responder: RefusingResponder(),
          turnStarter: RefusingTurnStarter(),
          turnSteerer: RefusingTurnSteerer(),
          readCursors: readCursors
        )
      )
    }
  }
}

// MARK: - Deterministic doubles

/// Minimal in-memory grant storage with an injectable load failure.
final class InMemoryGrantAuthorityStore: GrantAuthorityStorage, @unchecked Sendable {
  private let lock = NSLock()
  private var blob: Data? = Data()
  private var loadFailure: DeviceGrantAuthorityError?

  func load() throws -> GrantAuthorityLoadResult {
    lock.lock()
    defer { lock.unlock() }
    if let loadFailure { throw loadFailure }
    guard let blob else { throw DeviceGrantAuthorityError.authorityMissing }
    return blob.isEmpty ? .empty : .blob(blob)
  }

  func replace(blob: Data) throws {
    lock.lock()
    defer { lock.unlock() }
    self.blob = blob
  }

  func failLoads(with failure: DeviceGrantAuthorityError?) {
    lock.lock()
    defer { lock.unlock() }
    loadFailure = failure
  }
}

private struct RefusingStatementSigner: SessionStatementSigner {
  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    throw SessionClosedReason.deviceSignatureUnavailable
  }
}

private struct EmptyObservationSnapshotSource: ObservationSnapshotProviding {
  func currentObservationSnapshot() async -> CompanionStateSnapshot {
    CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000_000), latestSequence: 0, threads: [])
  }
}

private struct AlwaysReadyRuntime: NetworkRuntimeReadiness {
  func isReadyForStateChange() async -> Bool { true }
}

private struct RefusingResponder: CodexApprovalResponding {
  func respondToServerRequest(id: Int64, result: JSONValue) async throws {
    throw CodexRuntimeRequestError.notReady
  }

  func interruptTurn(threadID: String, turnID: String) async throws {
    throw CodexRuntimeRequestError.notReady
  }
}

private struct RefusingTurnStarter: CodexTurnStarting {
  func startTurn(threadID: String, prompt: String, policy: PhoneTurnPolicy) async throws -> String {
    throw CodexRuntimeRequestError.notReady
  }
}

private struct RefusingTurnSteerer: CodexTurnSteering {
  func steerTurn(threadID: String, turnID: String, prompt: String) async throws {
    throw CodexRuntimeRequestError.notReady
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
