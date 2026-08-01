import CodexAppServer
import CodexTestSupport
import CompanionProtocol
import Foundation
import XCTest

@testable import MacBridgeCore

/// Contract tests that drive the real app-server client and bridge domain
/// components through deterministic fake app-server scenarios, covering every
/// consumed notification and approval type plus fail-closed adversarial
/// shapes — without a live Codex process.
final class FakeAppServerContractTests: XCTestCase {
  func testDomainStoreAppliesFullTurnLifecycleFromFakeServer() async throws {
    let server = FakeCodexAppServer()
    server.stubResult(
      "thread/read",
      CodexAppServerFixtures.threadReadResult(
        CodexAppServerFixtures.thread(
          id: "thread-1",
          status: "idle",
          turns: [CodexAppServerFixtures.turn(id: "turn-0", status: "completed")]
        ))
    )
    server.stubResult(
      "turn/start",
      CodexAppServerFixtures.turnStartResult(turnID: "turn-1"),
      followUps: [CodexAppServerFixtures.turnStarted(turnID: "turn-1")]
    )

    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    var events = client.events.makeAsyncIterator()

    let threadResponse = try await client.request(
      method: "thread/read",
      params: .object([
        "threadId": .string("thread-1"),
        "includeTurns": .bool(true),
      ])
    )
    try await store.replaceThread(with: threadResponse["thread"])

    let turnResponse = try await client.request(
      method: "turn/start",
      params: .object(["threadId": .string("thread-1")])
    )
    _ = try await store.registerTurnStartResponse(
      threadID: "thread-1",
      response: turnResponse
    )

    try server.emit(
      CodexAppServerFixtures.agentMessageDelta(threadID: "thread-1", turnID: "turn-1"))
    try server.emit(
      CodexAppServerFixtures.planUpdated(threadID: "thread-1", turnID: "turn-1"))
    try server.emit(
      CodexAppServerFixtures.commandItemStarted(threadID: "thread-1", turnID: "turn-1"))
    try server.emit(
      CodexAppServerFixtures.commandItemCompleted(threadID: "thread-1", turnID: "turn-1"))
    try server.emit(
      CodexAppServerFixtures.diffUpdated(threadID: "thread-1", turnID: "turn-1"))
    try server.emit(
      CodexAppServerFixtures.threadStatusChanged(threadID: "thread-1", status: "active"))
    try server.emit(
      CodexAppServerFixtures.turnCompleted(turnID: "turn-1", status: "completed"))

    var results: [CodexDomainStoreResult] = []
    for _ in 0..<8 {
      guard let event = await events.next() else { break }
      results.append(try await store.apply(event))
    }
    await client.stop()

    XCTAssertEqual(results.count, 8)
    XCTAssertTrue(results.allSatisfy { $0 == .updated(threadID: "thread-1") })
    let snapshot = await store.snapshot(threadID: "thread-1")
    XCTAssertEqual(snapshot?.status, "active")
    XCTAssertNil(snapshot?.activeTurnID)
    XCTAssertEqual(snapshot?.lastTurnID, "turn-1")
    XCTAssertEqual(snapshot?.lastTurnStatus, "completed")
    XCTAssertTrue(
      server.serverRequestResponses().isEmpty,
      "The bridge must never answer server requests during a plain lifecycle."
    )
  }

  func testEveryApprovalKindIngestsAndResolvesThroughCompanionSnapshot() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    var events = client.events.makeAsyncIterator()
    try await store.replaceThread(
      with: CodexAppServerFixtures.thread(id: "thread-1", status: "active"))

    let startedAt = Date()
    try server.emit(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 101, threadID: "thread-1", turnID: "turn-1", startedAt: startedAt))
    try server.emit(
      CodexAppServerFixtures.networkApprovalRequest(
        rpcID: 102, threadID: "thread-1", turnID: "turn-1", startedAt: startedAt))
    try server.emit(
      CodexAppServerFixtures.fileChangeApprovalRequest(
        rpcID: 103, threadID: "thread-1", turnID: "turn-1", startedAt: startedAt))
    try server.emit(
      CodexAppServerFixtures.permissionsApprovalRequest(
        rpcID: 104, threadID: "thread-1", turnID: "turn-1", startedAt: startedAt))

    for _ in 0..<4 {
      let event = try await nextEvent(&events)
      let result = try await store.apply(event)
      XCTAssertEqual(result, .updated(threadID: "thread-1"))
    }

    let pending = await store.makeCompanionSnapshot(latestSequence: 4).pendingApprovals
    XCTAssertEqual(pending.count, 4)
    XCTAssertEqual(
      Set(pending.map(\.kind)),
      [.command, .network, .fileChange, .permissions]
    )
    XCTAssertTrue(pending.allSatisfy { $0.status == .pending })
    XCTAssertTrue(
      server.serverRequestResponses().isEmpty,
      "Ingesting approvals must never answer them automatically."
    )

    try server.emit(
      CodexAppServerFixtures.serverRequestResolved(
        requestID: 101, threadID: "thread-1", turnID: "turn-1"))
    let resolved = try await nextEvent(&events)
    _ = try await store.apply(resolved)
    await client.stop()

    let remaining = await store.makeCompanionSnapshot(latestSequence: 5).pendingApprovals
    XCTAssertEqual(remaining.count, 3)
    XCTAssertFalse(remaining.contains { $0.requestID == "101" })
  }

  func testUnknownNotificationWithoutThreadContextIsIgnored() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    var events = client.events.makeAsyncIterator()

    try server.emit(CodexAppServerFixtures.unknownNotification())
    let event = try await nextEvent(&events)
    let result = try await store.apply(event)
    await client.stop()

    XCTAssertEqual(result, .ignored)
  }

  func testEventForUnknownThreadDemandsSnapshotRebuild() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    var events = client.events.makeAsyncIterator()

    try server.emit(CodexAppServerFixtures.unknownNotification(threadID: "thread-ghost"))
    let event = try await nextEvent(&events)
    let result = try await store.apply(event)
    await client.stop()

    XCTAssertEqual(result, .snapshotRequired(threadID: "thread-ghost"))
  }

  func testUnknownServerRequestCreatesNoApprovalAndIsNeverAnswered() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    var events = client.events.makeAsyncIterator()
    try await store.replaceThread(
      with: CodexAppServerFixtures.thread(id: "thread-1", status: "active"))

    try server.emit(
      CodexAppServerFixtures.unknownServerRequest(
        rpcID: 900, threadID: "thread-1", turnID: "turn-9"))
    let event = try await nextEvent(&events)
    let result = try await store.apply(event)
    await client.stop()

    XCTAssertEqual(result, .updated(threadID: "thread-1"))
    let pending = await store.makeCompanionSnapshot(latestSequence: 1).pendingApprovals
    XCTAssertTrue(pending.isEmpty)
    XCTAssertNil(server.serverRequestResponse(rpcID: 900))
    XCTAssertTrue(server.serverRequestResponses().isEmpty)
  }

  func testInvalidAndExpiredApprovalRequestsAreRejected() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    var events = client.events.makeAsyncIterator()
    try await store.replaceThread(
      with: CodexAppServerFixtures.thread(id: "thread-1", status: "active"))

    try server.emit(
      CodexAppServerFixtures.invalidApprovalRequest(
        rpcID: 201, threadID: "thread-1", turnID: "turn-1"))
    let invalid = try await nextEvent(&events)
    do {
      _ = try await store.apply(invalid)
      XCTFail("Expected the field-incomplete approval request to be rejected.")
    } catch let error as PendingApprovalError {
      XCTAssertEqual(error, .invalidRequest)
    }

    try server.emit(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 202,
        threadID: "thread-1",
        turnID: "turn-1",
        startedAt: Date(timeIntervalSinceNow: -600)))
    let expired = try await nextEvent(&events)
    do {
      _ = try await store.apply(expired)
      XCTFail("Expected the expired approval request to be rejected.")
    } catch let error as PendingApprovalError {
      XCTAssertEqual(error, .expired)
    }
    await client.stop()

    let pending = await store.makeCompanionSnapshot(latestSequence: 2).pendingApprovals
    XCTAssertTrue(pending.isEmpty)
    XCTAssertTrue(server.serverRequestResponses().isEmpty)
  }

  func testMalformedServerLineFailsClosedAndConnectionRemainsUsable() async throws {
    let server = FakeCodexAppServer()
    server.stubResult("model/list", .object(["models": .array([])]))
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let store = CodexDomainStore()
    var events = client.events.makeAsyncIterator()

    server.emitRaw(CodexAppServerFixtures.malformedLine)
    let warning = try await nextEvent(&events)
    do {
      _ = try await store.apply(warning)
      XCTFail("Expected a protocol warning to fail closed in the router.")
    } catch let error as CodexEventRoutingError {
      XCTAssertEqual(error, .protocolWarning)
    }

    let models = try await client.request(method: "model/list")
    await client.stop()

    XCTAssertEqual(models["models"].array?.count, 0)
  }

  func testSupervisorRunsRealClientAgainstFakeServerAndDegradesOnCrash() async throws {
    let server = FakeCodexAppServer()
    let report = CodexCompatibilityReport(
      codexVersion: "0.146.0",
      schemaDigest: "expected"
    )
    let supervisor = CodexRuntimeSupervisor(
      policy: .init(
        supportedManifests: [
          .init(codexVersion: report.codexVersion, schemaDigest: report.schemaDigest)
        ]
      ),
      prober: StubCompatibilityProbe(report: report),
      makeSession: {
        LiveCodexRuntimeSession(
          client: CodexAppServerClient(transport: server, timeout: .seconds(2))
        )
      }
    )
    var states = supervisor.states.makeAsyncIterator()
    var events = supervisor.events.makeAsyncIterator()

    await supervisor.start()
    var currentState: CodexRuntimeState?
    for _ in 0..<4 {
      currentState = await states.next()
    }
    XCTAssertEqual(currentState, .ready(report))
    XCTAssertEqual(server.requests("initialize").count, 1)
    XCTAssertEqual(server.notifications("initialized").count, 1)

    try server.emit(CodexAppServerFixtures.threadArchived(threadID: "thread-1"))
    let forwarded = await events.next()
    XCTAssertEqual(
      forwarded,
      .notification(
        method: "thread/archived",
        params: .object(["threadId": .string("thread-1")])
      )
    )

    server.crash(exitStatus: 9)
    let degraded = await states.next()
    XCTAssertEqual(degraded, .degraded(.connectionClosed))
  }
}

private func nextEvent(
  _ events: inout AsyncStream<AppServerEvent>.AsyncIterator
) async throws -> AppServerEvent {
  let event = await events.next()
  return try XCTUnwrap(event)
}

private struct StubCompatibilityProbe: CodexCompatibilityProbing {
  let report: CodexCompatibilityReport

  func probe() async throws -> CodexCompatibilityReport {
    report
  }
}
