import CodexAppServer
import CodexTestSupport
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Contracts for automatic degraded-state recovery: a crashed Codex session
/// restarts through the full compatibility gate, in-flight work surfaces as
/// `outcomeUnknown`, and state is rebuilt only from authoritative
/// `thread/read` snapshots — never by replaying commands.
final class DegradedRecoveryContractTests: XCTestCase {
  private static let report = CodexCompatibilityReport(
    codexVersion: "0.146.0",
    schemaDigest: "expected"
  )

  func testCrashRestartsThroughGateAndRebuildsWithoutReplayingCommands() async throws {
    let firstServer = FakeCodexAppServer()
    let secondServer = FakeCodexAppServer()
    secondServer.stubResult(
      "thread/read",
      CodexAppServerFixtures.threadReadResult(
        CodexAppServerFixtures.thread(
          id: "thread-1",
          status: "idle",
          turns: [CodexAppServerFixtures.turn(id: "turn-1", status: "interrupted")]
        ))
    )
    let harness = try await RecoveryHarness.start(servers: [firstServer, secondServer])

    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .sendPrompt(threadID: "thread-1", prompt: "fixture-prompt", attachmentIDs: [])
    )
    _ = try await harness.ledger.register(deviceID: UUID(), command: command, at: Date())
    try await harness.ledger.markSubmitted(
      commandID: command.commandID,
      threadID: "thread-1",
      turnID: "turn-1",
      requestID: nil,
      at: Date()
    )

    firstServer.crash(exitStatus: 9)
    let rebuilt = await harness.log.eventually { events in
      events.contains(.rebuilt(threadIDs: ["thread-1"], droppedThreadIDs: []))
    }
    XCTAssertTrue(rebuilt, "Expected an automatic rebuild after the crash.")

    let record = await harness.ledger.record(commandID: command.commandID)
    XCTAssertEqual(record?.state, .outcomeUnknown)
    XCTAssertEqual(record?.resultCode, .bridgeRestartedBeforeOutcome)

    let snapshot = await harness.store.snapshot(threadID: "thread-1")
    XCTAssertNil(snapshot?.activeTurnID)
    XCTAssertEqual(snapshot?.lastTurnStatus, "interrupted")

    let state = await harness.supervisor.state()
    XCTAssertEqual(state, .ready(Self.report))
    let sentMethods = Set(secondServer.messages().compactMap { $0["method"].string })
    XCTAssertEqual(
      sentMethods, ["initialize", "initialized", "thread/read"],
      "Recovery must only read state; it must never replay state-changing commands."
    )
    await harness.shutdown()
  }

  func testUnreadableThreadIsDroppedInsteadOfGuessed() async throws {
    let firstServer = FakeCodexAppServer()
    let secondServer = FakeCodexAppServer()
    secondServer.stub("thread/read") { _, _ in
      .error(code: -32602, message: "Unknown thread")
    }
    let harness = try await RecoveryHarness.start(servers: [firstServer, secondServer])

    firstServer.crash(exitStatus: 9)
    let rebuilt = await harness.log.eventually { events in
      events.contains(.rebuilt(threadIDs: [], droppedThreadIDs: ["thread-1"]))
    }
    XCTAssertTrue(rebuilt, "Expected the unreadable thread to be dropped.")

    let snapshot = await harness.store.snapshot(threadID: "thread-1")
    XCTAssertNil(snapshot, "Stale state must not survive a failed authoritative re-read.")
    await harness.shutdown()
  }

  func testRepeatedStartupFailureRetriesWithBackoffUntilSuccess() async throws {
    let firstServer = FakeCodexAppServer()
    let recoveredServer = FakeCodexAppServer()
    recoveredServer.stubResult(
      "thread/read",
      CodexAppServerFixtures.threadReadResult(
        CodexAppServerFixtures.thread(id: "thread-1", status: "idle")
      )
    )
    let harness = try await RecoveryHarness.start(
      sessions: [
        LiveCodexRuntimeSession(
          client: CodexAppServerClient(transport: firstServer, timeout: .seconds(2))
        ),
        FailingRuntimeSession(),
        FailingRuntimeSession(),
        LiveCodexRuntimeSession(
          client: CodexAppServerClient(transport: recoveredServer, timeout: .seconds(2))
        ),
      ]
    )

    firstServer.crash(exitStatus: 9)
    let recovered = await harness.log.eventually(timeout: .seconds(5)) { events in
      events.contains { event in
        if case .rebuilt = event { return true }
        return false
      }
    }
    XCTAssertTrue(recovered, "Expected recovery to keep retrying until a session starts.")

    let events = await harness.log.all()
    let attempts = events.compactMap { event -> Int? in
      if case .recoveryStarted(let attempt) = event { return attempt }
      return nil
    }
    XCTAssertEqual(attempts, [1, 2, 3])
    let failures = events.filter { event in
      if case .recoveryFailed = event { return true }
      return false
    }
    XCTAssertEqual(failures.count, 2)
    let state = await harness.supervisor.state()
    XCTAssertEqual(state, .ready(Self.report))
    await harness.shutdown()
  }

  func testUnsupportedCodexAfterRestartFailsClosedWithoutRetry() async throws {
    let firstServer = FakeCodexAppServer()
    let secondServer = FakeCodexAppServer()
    let harness = try await RecoveryHarness.start(
      servers: [firstServer, secondServer],
      probeReports: [
        Self.report,
        CodexCompatibilityReport(codexVersion: "0.146.0", schemaDigest: "changed"),
      ]
    )

    firstServer.crash(exitStatus: 9)
    let blocked = await harness.log.eventually { events in
      events.contains(.runtimeState(.unsupported(.schemaMismatch)))
    }
    XCTAssertTrue(blocked, "Expected the changed schema to block the restart.")

    try await Task.sleep(for: .milliseconds(200))
    let events = await harness.log.all()
    let attempts = events.filter { event in
      if case .recoveryStarted = event { return true }
      return false
    }
    XCTAssertEqual(
      attempts.count, 1,
      "An unsupported runtime is terminal and must not be retried."
    )
    XCTAssertTrue(secondServer.messages().isEmpty)
    await harness.shutdown()
  }

  func testPersistentLedgerBulkUnknownTransitionPersistsAcrossReopen() async throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-recovery-test-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let databaseURL = directory.appendingPathComponent("ledger.sqlite")
    let key = SymmetricKey(data: Data(repeating: 0x51, count: 32))

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
    try await ledger.markInFlightOutcomesUnknown(at: Date(timeIntervalSince1970: 101))

    let record = await ledger.record(commandID: command.commandID)
    XCTAssertEqual(record?.state, .outcomeUnknown)

    let reopened = try PersistentCommandLedger(databaseURL: databaseURL, key: key)
    let persisted = await reopened.record(commandID: command.commandID)
    XCTAssertEqual(persisted?.state, .outcomeUnknown)
    XCTAssertEqual(persisted?.resultCode, .bridgeRestartedBeforeOutcome)
  }
}

// MARK: - Harness

private actor RecoveryEventLog {
  private var events: [CodexRecoveryEvent] = []

  func append(_ event: CodexRecoveryEvent) {
    events.append(event)
  }

  func all() -> [CodexRecoveryEvent] {
    events
  }

  func eventually(
    timeout: Duration = .seconds(2),
    _ condition: ([CodexRecoveryEvent]) -> Bool
  ) async -> Bool {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
      if condition(events) { return true }
      try? await Task.sleep(for: .milliseconds(10))
    }
    return condition(events)
  }
}

private struct RecoveryHarness {
  let supervisor: CodexRuntimeSupervisor
  let store: CodexDomainStore
  let ledger: InMemoryCommandLedger
  let coordinator: CodexRuntimeRecoveryCoordinator
  let log: RecoveryEventLog
  let logTask: Task<Void, Never>

  static func start(
    servers: [FakeCodexAppServer],
    probeReports: [CodexCompatibilityReport]? = nil
  ) async throws -> RecoveryHarness {
    try await start(
      sessions: servers.map { server in
        LiveCodexRuntimeSession(
          client: CodexAppServerClient(transport: server, timeout: .seconds(2))
        )
      },
      probeReports: probeReports
    )
  }

  static func start(
    sessions: [any CodexRuntimeSession],
    probeReports: [CodexCompatibilityReport]? = nil
  ) async throws -> RecoveryHarness {
    let report = CodexCompatibilityReport(codexVersion: "0.146.0", schemaDigest: "expected")
    let factory = SessionFactory(sessions)
    let supervisor = CodexRuntimeSupervisor(
      policy: .init(
        supportedManifests: [
          .init(codexVersion: report.codexVersion, schemaDigest: report.schemaDigest)
        ]
      ),
      prober: SequencedCompatibilityProbe(reports: probeReports ?? [report]),
      makeSession: { factory.next() }
    )
    let store = CodexDomainStore()
    try await store.replaceThread(
      with: CodexAppServerFixtures.thread(
        id: "thread-1",
        status: "active",
        turns: [CodexAppServerFixtures.turn(id: "turn-1", status: "inProgress")]
      ))
    let ledger = InMemoryCommandLedger()
    let coordinator = CodexRuntimeRecoveryCoordinator(
      supervisor: supervisor,
      store: store,
      ledger: ledger,
      restartDelay: .milliseconds(10),
      maximumRestartDelay: .milliseconds(40)
    )
    let log = RecoveryEventLog()
    let logTask = Task {
      for await event in coordinator.events {
        await log.append(event)
      }
    }
    await coordinator.start()
    await supervisor.start()
    return RecoveryHarness(
      supervisor: supervisor,
      store: store,
      ledger: ledger,
      coordinator: coordinator,
      log: log,
      logTask: logTask
    )
  }

  func shutdown() async {
    await coordinator.stop()
    await supervisor.stop()
    logTask.cancel()
  }
}

private final class SessionFactory: @unchecked Sendable {
  private let lock = NSLock()
  private let sessions: [any CodexRuntimeSession]
  private var index = 0

  init(_ sessions: [any CodexRuntimeSession]) {
    self.sessions = sessions
  }

  func next() -> any CodexRuntimeSession {
    lock.lock()
    defer { lock.unlock() }
    let session = sessions[min(index, sessions.count - 1)]
    index += 1
    return session
  }
}

private struct SequencedCompatibilityProbe: CodexCompatibilityProbing {
  let reports: [CodexCompatibilityReport]
  private let counter = ProbeCounter()

  func probe() async throws -> CodexCompatibilityReport {
    reports[min(counter.next(), reports.count - 1)]
  }
}

private final class ProbeCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0

  func next() -> Int {
    lock.lock()
    defer { lock.unlock() }
    let current = value
    value += 1
    return current
  }
}

private struct StartupFailure: Error {}

private struct FailingRuntimeSession: CodexRuntimeSession {
  let events: AsyncStream<AppServerEvent> = AsyncStream { $0.finish() }

  func start() async throws {
    throw StartupFailure()
  }

  func stop() async {}

  func startThread(projectID: String, policy: PhoneTurnPolicy) async throws -> String {
    throw CodexRuntimeRequestError.notReady
  }

  func readThread(threadID: String, includeTurns: Bool) async throws -> JSONValue {
    throw CodexRuntimeRequestError.notReady
  }

  func respondToServerRequest(id: Int64, result: JSONValue) async throws {
    throw CodexRuntimeRequestError.notReady
  }

  func interruptTurn(threadID: String, turnID: String) async throws {
    throw CodexRuntimeRequestError.notReady
  }

  func startTurn(
    threadID: String,
    prompt: String,
    policy: PhoneTurnPolicy
  ) async throws -> String {
    throw CodexRuntimeRequestError.notReady
  }

  func steerTurn(threadID: String, turnID: String, prompt: String) async throws {
    throw CodexRuntimeRequestError.notReady
  }
}
