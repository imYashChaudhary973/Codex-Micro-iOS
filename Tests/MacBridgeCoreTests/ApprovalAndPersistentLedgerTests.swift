import CodexAppServer
import CompanionProtocol
import CryptoKit
import Foundation
import SQLite3
import XCTest

@testable import MacBridgeCore

final class ApprovalAndPersistentLedgerTests: XCTestCase {
  func testApprovalSnapshotIsContentFreeAndMutationFailsClosed() async throws {
    let now = Date(timeIntervalSince1970: 1_754_000_000)
    let store = try await makeStoreWithActiveTurn()
    _ = try await store.apply(commandApproval(now: now), now: now)
    let snapshot = await store.makeCompanionSnapshot(
      latestSequence: 1,
      generatedAt: now,
      now: now
    )
    let approval = try XCTUnwrap(snapshot.pendingApprovals.first)
    let encoded = try JSONEncoder().encode(snapshot)
    let json = String(decoding: encoded, as: UTF8.self)

    XCTAssertEqual(approval.kind, .command)
    XCTAssertEqual(approval.status, .pending)
    XCTAssertFalse(json.contains("PRIVATE_COMMAND"))
    XCTAssertFalse(json.contains("/private/project"))

    do {
      _ = try await store.prepareApprovalResolution(
        requestID: approval.requestID,
        requestDigest: String(repeating: "0", count: 64),
        decision: .decline,
        now: now
      )
      XCTFail("A mutated approval digest must be rejected.")
    } catch let error as PendingApprovalError {
      XCTAssertEqual(error, .digestMismatch)
    }
  }

  func testApproveOnceRequiresFreshDigestBoundUserPresence() async throws {
    let now = Date(timeIntervalSince1970: 1_754_000_000)
    let store = try await makeStoreWithActiveTurn()
    _ = try await store.apply(commandApproval(now: now), now: now)
    let currentSnapshot = await store.makeCompanionSnapshot(latestSequence: 1, now: now)
    let approval = try XCTUnwrap(currentSnapshot.pendingApprovals.first)

    do {
      _ = try await store.prepareApprovalResolution(
        requestID: approval.requestID,
        requestDigest: approval.requestDigest,
        decision: .approveOnce,
        now: now
      )
      XCTFail("Approval without user presence must fail closed.")
    } catch let error as PendingApprovalError {
      XCTAssertEqual(error, .userPresenceRequired)
    }

    let wrongProof = ApprovalUserPresenceProof.verifiedForTesting(
      requestDigest: String(repeating: "f", count: 64),
      verifiedAt: now,
      expiresAt: now.addingTimeInterval(30)
    )
    do {
      _ = try await store.prepareApprovalResolution(
        requestID: approval.requestID,
        requestDigest: approval.requestDigest,
        decision: .approveOnce,
        userPresence: wrongProof,
        now: now
      )
      XCTFail("User presence for another request must be rejected.")
    } catch let error as PendingApprovalError {
      XCTAssertEqual(error, .invalidUserPresence)
    }

    let proof = ApprovalUserPresenceProof.verifiedForTesting(
      requestDigest: approval.requestDigest,
      verifiedAt: now,
      expiresAt: now.addingTimeInterval(30)
    )
    let prepared = try await store.prepareApprovalResolution(
      requestID: approval.requestID,
      requestDigest: approval.requestDigest,
      decision: .approveOnce,
      userPresence: proof,
      now: now
    )

    XCTAssertEqual(prepared.response, .object(["decision": .string("accept")]))
    XCTAssertFalse(prepared.shouldInterruptTurn)
  }

  func testPermissionDeclineGrantsNothingAndCancelRequestsInterrupt() async throws {
    let now = Date(timeIntervalSince1970: 1_754_000_000)

    let declineStore = try await makeStoreWithActiveTurn()
    _ = try await declineStore.apply(permissionApproval(id: 50, now: now), now: now)
    let declineSnapshot = await declineStore.makeCompanionSnapshot(latestSequence: 1, now: now)
    let declineApproval = try XCTUnwrap(declineSnapshot.pendingApprovals.first)
    let declined = try await declineStore.prepareApprovalResolution(
      requestID: declineApproval.requestID,
      requestDigest: declineApproval.requestDigest,
      decision: .decline,
      now: now
    )
    XCTAssertEqual(declined.response["permissions"], .object([:]))
    XCTAssertEqual(declined.response["scope"].string, "turn")
    XCTAssertFalse(declined.shouldInterruptTurn)

    let cancelStore = try await makeStoreWithActiveTurn()
    _ = try await cancelStore.apply(permissionApproval(id: 51, now: now), now: now)
    let cancelSnapshot = await cancelStore.makeCompanionSnapshot(latestSequence: 1, now: now)
    let cancelApproval = try XCTUnwrap(cancelSnapshot.pendingApprovals.first)
    let cancelled = try await cancelStore.prepareApprovalResolution(
      requestID: cancelApproval.requestID,
      requestDigest: cancelApproval.requestDigest,
      decision: .cancel,
      now: now
    )
    XCTAssertEqual(cancelled.response["permissions"], .object([:]))
    XCTAssertTrue(cancelled.shouldInterruptTurn)
  }

  func testExpiredAndAlreadyResolvingApprovalsCannotBeReused() async throws {
    let now = Date(timeIntervalSince1970: 1_754_000_000)
    let store = try await makeStoreWithActiveTurn()
    _ = try await store.apply(commandApproval(now: now), now: now)
    let currentSnapshot = await store.makeCompanionSnapshot(latestSequence: 1, now: now)
    let approval = try XCTUnwrap(currentSnapshot.pendingApprovals.first)
    _ = try await store.prepareApprovalResolution(
      requestID: approval.requestID,
      requestDigest: approval.requestDigest,
      decision: .decline,
      now: now
    )

    do {
      _ = try await store.prepareApprovalResolution(
        requestID: approval.requestID,
        requestDigest: approval.requestDigest,
        decision: .decline,
        now: now
      )
      XCTFail("A resolving request must not be reusable.")
    } catch let error as PendingApprovalError {
      XCTAssertEqual(error, .notPending)
    }

    let expiredStore = try await makeStoreWithActiveTurn()
    _ = try await expiredStore.apply(commandApproval(now: now), now: now)
    let expiredSnapshot = await expiredStore.makeCompanionSnapshot(latestSequence: 1, now: now)
    let expiredApproval = try XCTUnwrap(expiredSnapshot.pendingApprovals.first)
    do {
      _ = try await expiredStore.prepareApprovalResolution(
        requestID: expiredApproval.requestID,
        requestDigest: expiredApproval.requestDigest,
        decision: .decline,
        now: now.addingTimeInterval(121)
      )
      XCTFail("An expired approval must be rejected.")
    } catch let error as PendingApprovalError {
      XCTAssertEqual(error, .expired)
    }
  }

  func testPersistentLedgerEncryptsRecordsAndRecoversAmbiguousWork() async throws {
    let directory = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let databaseURL = directory.appendingPathComponent("ledger.sqlite")
    let key = SymmetricKey(data: Data(repeating: 0x42, count: 32))
    let commandID = UUID()
    let deviceID = UUID()
    let command = try ClientCommand(
      commandID: commandID,
      issuedAt: Date(timeIntervalSince1970: 100),
      body: .sendPrompt(
        threadID: "private-thread",
        prompt: "PRIVATE_PROMPT_MUST_NOT_BE_STORED",
        attachmentIDs: []
      )
    )

    let first = try PersistentCommandLedger(
      databaseURL: databaseURL,
      key: key,
      recoveryDate: Date(timeIntervalSince1970: 101)
    )
    _ = try await first.register(deviceID: deviceID, command: command)
    try await first.markSubmitted(
      commandID: commandID,
      threadID: "private-thread",
      turnID: "private-turn",
      at: Date(timeIntervalSince1970: 102)
    )

    let databaseBytes = try Data(contentsOf: databaseURL)
    let databaseText = String(decoding: databaseBytes, as: UTF8.self)
    XCTAssertFalse(databaseText.contains("PRIVATE_PROMPT_MUST_NOT_BE_STORED"))
    XCTAssertFalse(databaseText.contains("private-thread"))
    XCTAssertFalse(databaseText.contains("private-turn"))
    let permissions = try XCTUnwrap(
      FileManager.default.attributesOfItem(atPath: databaseURL.path)[.posixPermissions]
        as? NSNumber
    )
    XCTAssertEqual(permissions.intValue & 0o777, 0o600)

    let recoveredAt = Date(timeIntervalSince1970: 200)
    let replacement = try PersistentCommandLedger(
      databaseURL: databaseURL,
      key: key,
      recoveryDate: recoveredAt
    )
    let recovered = await replacement.record(commandID: commandID)
    XCTAssertEqual(recovered?.state, .outcomeUnknown)
    XCTAssertEqual(recovered?.resultCode, .bridgeRestartedBeforeOutcome)
    XCTAssertEqual(recovered?.updatedAt, recoveredAt)

    guard
      case .replay(let replayed) = try await replacement.register(
        deviceID: deviceID,
        command: command
      )
    else {
      return XCTFail("Recovered work must replay rather than execute again.")
    }
    XCTAssertEqual(replayed.state, .outcomeUnknown)
  }

  func testPersistentLedgerRejectsWrongKeyAndPurgesOldTerminalRecords() async throws {
    let directory = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let databaseURL = directory.appendingPathComponent("ledger.sqlite")
    let key = SymmetricKey(data: Data(repeating: 0x24, count: 32))
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(timeIntervalSince1970: 100),
      body: .interruptTurn(threadID: "thread-1", turnID: "turn-1")
    )
    let ledger = try PersistentCommandLedger(databaseURL: databaseURL, key: key)
    _ = try await ledger.register(
      deviceID: UUID(),
      command: command,
      at: Date(timeIntervalSince1970: 100)
    )
    try await ledger.finish(
      commandID: command.commandID,
      state: .succeeded,
      resultCode: .completed,
      at: Date(timeIntervalSince1970: 101)
    )
    try await ledger.purgeTerminalRecords(olderThan: Date(timeIntervalSince1970: 102))
    let purgedRecord = await ledger.record(commandID: command.commandID)
    XCTAssertNil(purgedRecord)

    let wrongKey = SymmetricKey(data: Data(repeating: 0x25, count: 32))
    XCTAssertNoThrow(
      try PersistentCommandLedger(databaseURL: databaseURL, key: wrongKey),
      "A purged database contains no ciphertext to decrypt."
    )

    let secondCommand = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(timeIntervalSince1970: 200),
      body: .interruptTurn(threadID: "thread-2", turnID: "turn-2")
    )
    _ = try await ledger.register(deviceID: UUID(), command: secondCommand)
    XCTAssertThrowsError(
      try PersistentCommandLedger(databaseURL: databaseURL, key: wrongKey)
    ) { error in
      XCTAssertEqual(error as? PersistentCommandLedgerError, .invalidRecord)
    }
  }

  func testPersistentLedgerRejectsUnknownSchemaVersion() throws {
    let directory = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let databaseURL = directory.appendingPathComponent("future.sqlite")
    var database: OpaquePointer?
    XCTAssertEqual(sqlite3_open(databaseURL.path, &database), SQLITE_OK)
    XCTAssertEqual(sqlite3_exec(database, "PRAGMA user_version=99", nil, nil, nil), SQLITE_OK)
    XCTAssertEqual(sqlite3_close(database), SQLITE_OK)

    let key = SymmetricKey(data: Data(repeating: 0x77, count: 32))
    XCTAssertThrowsError(
      try PersistentCommandLedger(databaseURL: databaseURL, key: key)
    ) { error in
      XCTAssertEqual(
        error as? PersistentCommandLedgerError,
        .unsupportedSchemaVersion
      )
    }
  }

  private func makeStoreWithActiveTurn() async throws -> CodexDomainStore {
    let store = CodexDomainStore()
    try await store.replaceThread(
      with: .object([
        "id": .string("thread-1"),
        "status": .object(["type": .string("active")]),
        "turns": .array([
          .object([
            "id": .string("turn-1"),
            "status": .string("inProgress"),
          ])
        ]),
      ])
    )
    return store
  }

  private func commandApproval(now: Date) -> AppServerEvent {
    .serverRequest(
      id: 42,
      method: "item/commandExecution/requestApproval",
      params: .object([
        "threadId": .string("thread-1"),
        "turnId": .string("turn-1"),
        "itemId": .string("item-1"),
        "startedAtMs": .integer(Int64(now.timeIntervalSince1970 * 1_000)),
        "command": .string("PRIVATE_COMMAND"),
        "cwd": .string("/private/project"),
      ])
    )
  }

  private func permissionApproval(id: Int64, now: Date) -> AppServerEvent {
    .serverRequest(
      id: id,
      method: "item/permissions/requestApproval",
      params: .object([
        "threadId": .string("thread-1"),
        "turnId": .string("turn-1"),
        "itemId": .string("item-permission"),
        "startedAtMs": .integer(Int64(now.timeIntervalSince1970 * 1_000)),
        "cwd": .string("/private/project"),
        "permissions": .object([
          "network": .object(["enabled": .bool(true)])
        ]),
      ])
    )
  }

  private func makeTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-micro-ledger-test-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    return url
  }
}
