import CodexAppServer
import CompanionProtocol
import Foundation
import XCTest

@testable import MacBridgeCore

final class CodexPhase1RuntimeTests: XCTestCase {
  func testCompatibilityPolicyRequiresExactVersionAndDigest() {
    let policy = CodexCompatibilityPolicy(
      supportedManifests: [
        .init(codexVersion: "0.146.0", schemaDigest: "expected")
      ]
    )

    XCTAssertEqual(
      policy.evaluate(.init(codexVersion: "0.146.0", schemaDigest: "expected")),
      .supported
    )
    XCTAssertEqual(
      policy.evaluate(.init(codexVersion: "0.147.0", schemaDigest: "expected")),
      .unsupportedVersion
    )
    XCTAssertEqual(
      policy.evaluate(.init(codexVersion: "0.146.0", schemaDigest: "changed")),
      .schemaMismatch
    )
  }

  func testSchemaDigestIgnoresJSONKeyOrderButDetectsContentChange() throws {
    let first = try makeTemporaryDirectory()
    let second = try makeTemporaryDirectory()
    let changed = try makeTemporaryDirectory()
    defer {
      try? FileManager.default.removeItem(at: first)
      try? FileManager.default.removeItem(at: second)
      try? FileManager.default.removeItem(at: changed)
    }

    let firstData = Data(#"{"alpha":1,"beta":{"one":true,"two":false}}"#.utf8)
    let secondData = Data(#"{"beta":{"two":false,"one":true},"alpha":1}"#.utf8)
    let changedData = Data(#"{"alpha":2,"beta":{"one":true,"two":false}}"#.utf8)
    try firstData
      .write(to: first.appendingPathComponent("schema.json"))
    try secondData
      .write(to: second.appendingPathComponent("schema.json"))
    try changedData
      .write(to: changed.appendingPathComponent("schema.json"))

    XCTAssertEqual(
      try CodexSchemaDigest.canonicalize(firstData),
      try CodexSchemaDigest.canonicalize(secondData)
    )

    let firstDigest = try CodexSchemaDigest.digest(directory: first)
    let secondDigest = try CodexSchemaDigest.digest(directory: second)
    let changedDigest = try CodexSchemaDigest.digest(directory: changed)

    XCTAssertEqual(firstDigest, secondDigest)
    XCTAssertNotEqual(firstDigest, changedDigest)
  }

  func testRouterKeepsConcurrentTurnsBoundToTheirExplicitThreads() throws {
    var router = CodexEventRouter()
    try router.registerThreadSnapshot(
      .object([
        "id": .string("thread-1"),
        "turns": .array([.object(["id": .string("turn-1")])]),
      ])
    )
    try router.registerThreadSnapshot(
      .object([
        "id": .string("thread-2"),
        "turns": .array([.object(["id": .string("turn-2")])]),
      ])
    )

    let routed = try router.route(
      .notification(
        method: "turn/completed",
        params: .object([
          "turn": .object(["id": .string("turn-2"), "status": .string("completed")])
        ])
      )
    )

    XCTAssertEqual(routed?.threadID, "thread-2")
    XCTAssertEqual(routed?.turnID, "turn-2")
  }

  func testRouterFailsClosedForUnknownOrConflictingTurn() throws {
    var router = CodexEventRouter()
    XCTAssertThrowsError(
      try router.route(
        .notification(
          method: "turn/started",
          params: .object(["turn": .object(["id": .string("turn-unknown")])])
        )
      )
    ) { error in
      XCTAssertEqual(error as? CodexEventRoutingError, .unknownTurn("turn-unknown"))
    }

    _ = try router.registerTurnStartResponse(
      threadID: "thread-1",
      response: .object(["turn": .object(["id": .string("turn-1")])])
    )
    XCTAssertThrowsError(
      try router.route(
        .serverRequest(
          id: 42,
          method: "item/commandExecution/requestApproval",
          params: .object([
            "threadId": .string("thread-2"),
            "turnId": .string("turn-1"),
          ])
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? CodexEventRoutingError,
        .conflictingTurnRoute(turnID: "turn-1")
      )
    }
  }

  func testDomainStoreUpdatesOnlyTheRoutedThread() async throws {
    let store = CodexDomainStore()
    try await store.replaceThread(
      with: .object([
        "id": .string("thread-1"),
        "status": .object(["type": .string("idle")]),
        "turns": .array([]),
      ])
    )
    _ = try await store.registerTurnStartResponse(
      threadID: "thread-1",
      response: .object([
        "turn": .object(["id": .string("turn-1")])
      ])
    )

    let result = try await store.apply(
      .notification(
        method: "turn/started",
        params: .object([
          "turn": .object([
            "id": .string("turn-1"),
            "status": .string("inProgress"),
          ])
        ])
      )
    )
    let snapshot = await store.snapshot(threadID: "thread-1")

    XCTAssertEqual(result, .updated(threadID: "thread-1"))
    XCTAssertEqual(snapshot?.activeTurnID, "turn-1")
  }

  func testDomainStoreBuildsContentFreeNormalizedSnapshot() async throws {
    let store = CodexDomainStore()
    try await store.replaceThread(
      with: .object([
        "id": .string("thread-2"),
        "status": .object(["type": .string("unexpectedFutureState")]),
        "turns": .array([
          .object([
            "id": .string("turn-2"),
            "status": .string("futureTurnState"),
            "items": .array([
              .object(["text": .string("must not enter the companion snapshot")])
            ]),
          ])
        ]),
      ])
    )

    let generatedAt = Date(timeIntervalSince1970: 1_754_000_000)
    let snapshot = await store.makeCompanionSnapshot(
      latestSequence: 9,
      generatedAt: generatedAt
    )
    let encoded = try JSONEncoder().encode(snapshot)
    let json = String(decoding: encoded, as: UTF8.self)

    XCTAssertEqual(snapshot.generatedAt, generatedAt)
    XCTAssertEqual(snapshot.latestSequence, 9)
    XCTAssertEqual(snapshot.threads.first?.status, .unknown)
    XCTAssertEqual(snapshot.threads.first?.lastTurnStatus, .unknown)
    XCTAssertFalse(json.contains("must not enter"))
  }

  func testProtocolMinorUpdateStillDecodesLegacySnapshotWithoutApprovals() throws {
    let legacy = LegacySnapshot(
      protocolVersion: .init(major: 1, minor: 0),
      generatedAt: Date(timeIntervalSince1970: 1_754_000_000),
      latestSequence: 3,
      threads: []
    )
    let data = try JSONEncoder().encode(legacy)
    let decoded = try JSONDecoder().decode(CompanionStateSnapshot.self, from: data)

    XCTAssertEqual(decoded.protocolVersion, .init(major: 1, minor: 0))
    XCTAssertTrue(decoded.pendingApprovals.isEmpty)
  }

  func testSupervisorBlocksUnsupportedCodexBeforeStartingSession() async {
    let session = FakeRuntimeSession()
    let supervisor = CodexRuntimeSupervisor(
      policy: .init(
        supportedManifests: [.init(codexVersion: "0.146.0", schemaDigest: "expected")]
      ),
      prober: FakeCompatibilityProbe(
        report: .init(codexVersion: "0.147.0", schemaDigest: "other")
      ),
      makeSession: { session }
    )

    await supervisor.start()
    let state = await supervisor.state()

    XCTAssertEqual(state, .unsupported(.unsupportedVersion))
    XCTAssertFalse(session.didStart)
  }

  func testSupervisorForwardsEventsAndDegradesWhenSessionCloses() async {
    let report = CodexCompatibilityReport(codexVersion: "0.146.0", schemaDigest: "expected")
    let session = FakeRuntimeSession()
    let supervisor = CodexRuntimeSupervisor(
      policy: .init(
        supportedManifests: [
          .init(codexVersion: report.codexVersion, schemaDigest: report.schemaDigest)
        ]
      ),
      prober: FakeCompatibilityProbe(report: report),
      makeSession: { session }
    )
    var eventIterator = supervisor.events.makeAsyncIterator()
    var stateIterator = supervisor.states.makeAsyncIterator()

    await supervisor.start()
    session.yield(
      .notification(
        method: "thread/archived",
        params: .object([
          "threadId": .string("thread-1")
        ])))
    session.finish()

    let forwardedEvent = await eventIterator.next()
    XCTAssertEqual(
      forwardedEvent,
      .notification(
        method: "thread/archived",
        params: .object(["threadId": .string("thread-1")])
      ))
    var lastState: CodexRuntimeState?
    for _ in 0..<5 {
      lastState = await stateIterator.next()
    }
    XCTAssertEqual(lastState, .degraded(.connectionClosed))
  }

  private func makeTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-micro-test-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    return url
  }
}

private struct LegacySnapshot: Codable {
  let protocolVersion: ProtocolVersion
  let generatedAt: Date
  let latestSequence: UInt64
  let threads: [CompanionThreadState]
}

private struct FakeCompatibilityProbe: CodexCompatibilityProbing {
  let report: CodexCompatibilityReport

  func probe() async throws -> CodexCompatibilityReport {
    report
  }
}

private final class FakeRuntimeSession: CodexRuntimeSession, @unchecked Sendable {
  let events: AsyncStream<AppServerEvent>
  private let continuation: AsyncStream<AppServerEvent>.Continuation
  private let lock = NSLock()
  private var started = false

  var didStart: Bool {
    lock.withLock { started }
  }

  init() {
    let pair = AsyncStream<AppServerEvent>.makeStream()
    events = pair.stream
    continuation = pair.continuation
  }

  func start() async throws {
    lock.withLock { started = true }
  }

  func stop() async {
    continuation.finish()
  }

  func yield(_ event: AppServerEvent) {
    continuation.yield(event)
  }

  func finish() {
    continuation.finish()
  }
}
