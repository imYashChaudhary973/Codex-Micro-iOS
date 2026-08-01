import CodexAppServer
import CodexTestSupport
import CompanionProtocol
import Foundation
import XCTest

@testable import MacBridgeCore

/// End-to-end contracts for phone-originated approval resolution: fake
/// app-server → real client → domain store → executor → ledger, covering
/// every decision path, reconciliation, ambiguity, and fail-closed rejection.
final class ApprovalWiringContractTests: XCTestCase {
  func testDeclineIsSentReconciledAndConfirmedEndToEnd() async throws {
    let pipeline = try await Pipeline.start()
    let approval = try await pipeline.ingestApproval(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 42, threadID: "thread-1", turnID: "turn-1", startedAt: Date()))

    let command = try makeResolveCommand(approval: approval, decision: .decline)
    async let pendingOutcome = pipeline.executor.execute(
      command: command,
      deviceID: UUID()
    )
    let response = try await pipeline.waitForResponse(rpcID: 42)
    XCTAssertEqual(response["result"]["decision"].string, "decline")
    try pipeline.server.emit(
      CodexAppServerFixtures.serverRequestResolved(
        requestID: 42, threadID: "thread-1", turnID: "turn-1"))
    let outcome = try await pendingOutcome

    guard case .confirmed(let record) = outcome else {
      XCTFail("Expected confirmation, received \(outcome).")
      return
    }
    XCTAssertEqual(record.state, .succeeded)
    XCTAssertEqual(record.resultCode, .completed)
    XCTAssertEqual(record.threadID, "thread-1")
    XCTAssertEqual(record.turnID, "turn-1")
    XCTAssertEqual(record.requestID, "42")
    let pending = await pipeline.store
      .makeCompanionSnapshot(latestSequence: 1).pendingApprovals
    XCTAssertTrue(pending.isEmpty)
    XCTAssertEqual(pipeline.server.serverRequestResponses().count, 1)
    await pipeline.shutdown()
  }

  func testApproveOnceSurvivesInstantConfirmationRaceAndReplaysIdempotently() async throws {
    let pipeline = try await Pipeline.start()
    let approval = try await pipeline.ingestApproval(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 43, threadID: "thread-1", turnID: "turn-1", startedAt: Date()))
    pipeline.server.onServerRequestResponse(
      rpcID: 43,
      emit: [
        CodexAppServerFixtures.serverRequestResolved(
          requestID: 43, threadID: "thread-1", turnID: "turn-1")
      ])

    let now = Date()
    let proof = ApprovalUserPresenceProof.verifiedForTesting(
      requestDigest: approval.requestDigest,
      verifiedAt: now,
      expiresAt: now.addingTimeInterval(30)
    )
    let command = try makeResolveCommand(approval: approval, decision: .approveOnce)
    let deviceID = UUID()
    let outcome = try await pipeline.executor.execute(
      command: command,
      deviceID: deviceID,
      userPresence: proof,
      now: now
    )

    guard case .confirmed(let record) = outcome else {
      XCTFail("Expected confirmation, received \(outcome).")
      return
    }
    XCTAssertEqual(record.state, .succeeded)
    let response = try XCTUnwrap(pipeline.server.serverRequestResponse(rpcID: 43))
    XCTAssertEqual(response["result"]["decision"].string, "accept")

    let replay = try await pipeline.executor.execute(
      command: command,
      deviceID: deviceID,
      userPresence: proof,
      now: now
    )
    guard case .replayed(let replayedRecord) = replay else {
      XCTFail("Expected an idempotent replay, received \(replay).")
      return
    }
    XCTAssertEqual(replayedRecord.state, .succeeded)
    XCTAssertEqual(
      pipeline.server.serverRequestResponses().count, 1,
      "A replayed command must never send a second response."
    )
    await pipeline.shutdown()
  }

  func testApproveOnceWithoutPresenceProofSendsNothing() async throws {
    let pipeline = try await Pipeline.start()
    let approval = try await pipeline.ingestApproval(
      CodexAppServerFixtures.fileChangeApprovalRequest(
        rpcID: 44, threadID: "thread-1", turnID: "turn-1", startedAt: Date()))

    let command = try makeResolveCommand(approval: approval, decision: .approveOnce)
    let outcome = try await pipeline.executor.execute(command: command, deviceID: UUID())

    guard case .rejectedByPolicy(let record, let reason) = outcome else {
      XCTFail("Expected a policy rejection, received \(outcome).")
      return
    }
    XCTAssertEqual(reason, .userPresenceRequired)
    XCTAssertEqual(record.state, .declined)
    XCTAssertEqual(record.resultCode, .rejectedByPolicy)
    XCTAssertTrue(pipeline.server.serverRequestResponses().isEmpty)
    let pending = await pipeline.store
      .makeCompanionSnapshot(latestSequence: 1).pendingApprovals
    XCTAssertEqual(pending.first?.status, .pending)
    await pipeline.shutdown()
  }

  func testMutatedDigestAndExpiredApprovalFailClosedWithoutSending() async throws {
    let pipeline = try await Pipeline.start()
    let approval = try await pipeline.ingestApproval(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 45, threadID: "thread-1", turnID: "turn-1", startedAt: Date()))

    let mutated = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .resolveApproval(
        requestID: approval.requestID,
        decision: .decline,
        requestDigest: String(repeating: "0", count: 64)
      )
    )
    let mutatedOutcome = try await pipeline.executor.execute(
      command: mutated,
      deviceID: UUID()
    )
    guard case .rejectedByPolicy(_, let mutatedReason) = mutatedOutcome else {
      XCTFail("Expected a policy rejection, received \(mutatedOutcome).")
      return
    }
    XCTAssertEqual(mutatedReason, .digestMismatch)

    let lateCommand = try makeResolveCommand(approval: approval, decision: .decline)
    let lateOutcome = try await pipeline.executor.execute(
      command: lateCommand,
      deviceID: UUID(),
      now: Date().addingTimeInterval(121)
    )
    guard case .rejectedByPolicy(_, let lateReason) = lateOutcome else {
      XCTFail("Expected a policy rejection, received \(lateOutcome).")
      return
    }
    XCTAssertEqual(lateReason, .expired)
    XCTAssertTrue(pipeline.server.serverRequestResponses().isEmpty)
    await pipeline.shutdown()
  }

  func testPermissionsCancelSendsTurnScopedDenialAndInterruptsExactTurn() async throws {
    let pipeline = try await Pipeline.start()
    let approval = try await pipeline.ingestApproval(
      CodexAppServerFixtures.permissionsApprovalRequest(
        rpcID: 51, threadID: "thread-1", turnID: "turn-1", startedAt: Date()))

    let command = try makeResolveCommand(approval: approval, decision: .cancel)
    async let pendingOutcome = pipeline.executor.execute(
      command: command,
      deviceID: UUID()
    )
    let response = try await pipeline.waitForResponse(rpcID: 51)
    XCTAssertEqual(response["result"]["permissions"], .object([:]))
    XCTAssertEqual(response["result"]["scope"].string, "turn")
    XCTAssertEqual(response["result"]["strictAutoReview"].bool, true)
    try pipeline.server.emit(
      CodexAppServerFixtures.serverRequestResolved(
        requestID: 51, threadID: "thread-1", turnID: "turn-1"))
    let outcome = try await pendingOutcome

    guard case .confirmed(let record) = outcome else {
      XCTFail("Expected confirmation, received \(outcome).")
      return
    }
    XCTAssertEqual(record.turnID, "turn-1")
    let interrupt = try XCTUnwrap(pipeline.server.requests("turn/interrupt").first)
    XCTAssertEqual(interrupt["params"]["threadId"].string, "thread-1")
    XCTAssertEqual(interrupt["params"]["turnId"].string, "turn-1")
    await pipeline.shutdown()
  }

  func testMissingConfirmationYieldsOutcomeUnknownWithoutResend() async throws {
    let pipeline = try await Pipeline.start(resolutionTimeout: .milliseconds(150))
    let approval = try await pipeline.ingestApproval(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 46, threadID: "thread-1", turnID: "turn-1", startedAt: Date()))

    let command = try makeResolveCommand(approval: approval, decision: .decline)
    let outcome = try await pipeline.executor.execute(command: command, deviceID: UUID())

    guard case .outcomeUnknown(let record) = outcome else {
      XCTFail("Expected an unknown outcome, received \(outcome).")
      return
    }
    XCTAssertEqual(record.state, .outcomeUnknown)
    XCTAssertEqual(record.resultCode, .confirmationTimedOut)
    XCTAssertEqual(
      pipeline.server.serverRequestResponses().count, 1,
      "An unconfirmed response must never be resent."
    )
    let pending = await pipeline.store
      .makeCompanionSnapshot(latestSequence: 1).pendingApprovals
    XCTAssertEqual(pending.first?.status, .outcomeUnknown)
    await pipeline.shutdown()
  }

  func testSendFailureAfterConnectionLossFailsWithoutRetry() async throws {
    let pipeline = try await Pipeline.start()
    let approval = try await pipeline.ingestApproval(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 47, threadID: "thread-1", turnID: "turn-1", startedAt: Date()))

    pipeline.server.crash(exitStatus: 9)
    await pipeline.pump.value

    let command = try makeResolveCommand(approval: approval, decision: .decline)
    let outcome = try await pipeline.executor.execute(command: command, deviceID: UUID())

    guard case .sendFailed(let record) = outcome else {
      XCTFail("Expected a send failure, received \(outcome).")
      return
    }
    XCTAssertEqual(record.state, .failed)
    XCTAssertEqual(record.resultCode, .codexUnavailable)
    XCTAssertTrue(pipeline.server.serverRequestResponses().isEmpty)
    let pending = await pipeline.store
      .makeCompanionSnapshot(latestSequence: 1).pendingApprovals
    XCTAssertEqual(pending.first?.status, .outcomeUnknown)
  }

  func testNonApprovalCommandIsRejectedBeforeLedgerRegistration() async throws {
    let pipeline = try await Pipeline.start()
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .interruptTurn(threadID: "thread-1", turnID: "turn-1")
    )

    do {
      _ = try await pipeline.executor.execute(command: command, deviceID: UUID())
      XCTFail("Expected the wrong command kind to be rejected.")
    } catch let error as ApprovalExecutionError {
      XCTAssertEqual(error, .unsupportedCommand)
    }
    let record = await pipeline.ledger.record(commandID: command.commandID)
    XCTAssertNil(record)
    await pipeline.shutdown()
  }

  private func makeResolveCommand(
    approval: CompanionPendingApproval,
    decision: CompanionApprovalDecision
  ) throws -> ClientCommand {
    try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .resolveApproval(
        requestID: approval.requestID,
        decision: decision,
        requestDigest: approval.requestDigest
      )
    )
  }
}

private struct PipelineTimeout: Error {}

/// Fake server, real client, domain store, ledger, and executor wired the way
/// the Mac app will wire them, with an event pump feeding the store and the
/// executor's reconciliation input.
private struct Pipeline {
  let server: FakeCodexAppServer
  let client: CodexAppServerClient
  let store: CodexDomainStore
  let ledger: InMemoryCommandLedger
  let executor: ApprovalResolutionExecutor
  let pump: Task<Void, Never>

  static func start(resolutionTimeout: Duration = .seconds(2)) async throws -> Pipeline {
    let server = FakeCodexAppServer()
    server.stubResult("turn/interrupt", .object([:]))
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    try await store.replaceThread(
      with: CodexAppServerFixtures.thread(
        id: "thread-1",
        status: "active",
        turns: [CodexAppServerFixtures.turn(id: "turn-1", status: "inProgress")]
      ))
    let ledger = InMemoryCommandLedger()
    let executor = ApprovalResolutionExecutor(
      store: store,
      ledger: ledger,
      responder: client,
      resolutionTimeout: resolutionTimeout
    )
    let pump = Task {
      for await event in client.events {
        _ = try? await store.apply(event)
        if case .notification(let method, let params) = event,
          method == "serverRequest/resolved"
        {
          let requestID =
            params["requestId"].string ?? params["requestId"].integer.map(String.init)
          if let requestID {
            await executor.noteServerRequestResolved(requestID: requestID)
          }
        }
      }
    }
    return Pipeline(
      server: server,
      client: client,
      store: store,
      ledger: ledger,
      executor: executor,
      pump: pump
    )
  }

  func ingestApproval(_ message: JSONValue) async throws -> CompanionPendingApproval {
    let requestID = message["id"].integer.map(String.init)
    try server.emit(message)
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while ContinuousClock.now < deadline {
      let pending = await store.makeCompanionSnapshot(latestSequence: 0).pendingApprovals
      if let approval = pending.first(where: { $0.requestID == requestID }) {
        return approval
      }
      try await Task.sleep(for: .milliseconds(10))
    }
    throw PipelineTimeout()
  }

  func waitForResponse(rpcID: Int64) async throws -> JSONValue {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while ContinuousClock.now < deadline {
      if let response = server.serverRequestResponse(rpcID: rpcID) {
        return response
      }
      try await Task.sleep(for: .milliseconds(10))
    }
    throw PipelineTimeout()
  }

  func shutdown() async {
    pump.cancel()
    await client.stop()
  }
}
