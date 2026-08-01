import CodexAppServer
import CodexTestSupport
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Contracts for the composition root the Mac app hosts: lazy authoritative
/// thread rebuilds, approval execution, journaled snapshot emission, clean
/// suspend/resume, crash recovery, and the Application Support ledger path.
final class BridgeAssemblyContractTests: XCTestCase {
  func testUnknownThreadEventTriggersAuthoritativeRebuildAndJournaledSnapshot() async throws {
    let server = FakeCodexAppServer()
    server.stubResult(
      "thread/read",
      CodexAppServerFixtures.threadReadResult(
        CodexAppServerFixtures.thread(id: "thread-1", status: "active")
      )
    )
    let harness = try await AssemblyHarness.start(servers: [server])

    try server.emit(
      CodexAppServerFixtures.threadStatusChanged(threadID: "thread-1", status: "active"))
    let rebuilt = await harness.updateLog.eventually { updates in
      updates.contains { update in
        if case .stateChanged = update { return true }
        return false
      }
    }
    XCTAssertTrue(rebuilt, "Expected a state change after the lazy rebuild.")

    let snapshot = await harness.assembly.snapshot()
    XCTAssertEqual(snapshot.threads.map(\.threadID), ["thread-1"])
    XCTAssertEqual(snapshot.latestSequence, 1)
    let replay = try await harness.assembly.replay(after: 0)
    guard case .events(let entries) = replay else {
      return XCTFail("Expected replayable events, received \(replay).")
    }
    XCTAssertEqual(entries.map(\.event), [.threadUpdated(threadID: "thread-1")])
    XCTAssertEqual(server.requests("thread/read").count, 1)
    await harness.shutdown()
  }

  func testApprovalExecutesEndToEndWithRedactedLogging() async throws {
    let server = FakeCodexAppServer()
    server.stubResult(
      "thread/read",
      CodexAppServerFixtures.threadReadResult(
        CodexAppServerFixtures.thread(
          id: "thread-1",
          status: "active",
          turns: [CodexAppServerFixtures.turn(id: "turn-1", status: "inProgress")]
        )
      )
    )
    let harness = try await AssemblyHarness.start(servers: [server])
    try server.emit(
      CodexAppServerFixtures.threadStatusChanged(threadID: "thread-1", status: "active"))

    try server.emit(
      .object([
        "id": .integer(42),
        "method": .string("item/commandExecution/requestApproval"),
        "params": .object([
          "threadId": .string("thread-1"),
          "turnId": .string("turn-1"),
          "itemId": .string("item-1"),
          "startedAtMs": .integer(Int64(Date().timeIntervalSince1970 * 1_000)),
          "command": .string("SENTINEL_COMMAND"),
          "cwd": .string("/sentinel/private/path"),
        ]),
      ]))
    let ingested = await harness.updateLog.eventually { _ in
      true
    }
    XCTAssertTrue(ingested)
    let approval = try await harness.pendingApproval(requestID: "42")

    server.onServerRequestResponse(
      rpcID: 42,
      emit: [
        CodexAppServerFixtures.serverRequestResolved(
          requestID: 42, threadID: "thread-1", turnID: "turn-1")
      ])
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .resolveApproval(
        requestID: approval.requestID,
        decision: .decline,
        requestDigest: approval.requestDigest
      )
    )
    let outcome = try await harness.assembly.resolveApproval(
      command: command,
      deviceID: UUID()
    )
    guard case .confirmed = outcome else {
      return XCTFail("Expected confirmation, received \(outcome).")
    }

    let cleared = await harness.updateLog.eventually { _ in true }
    XCTAssertTrue(cleared)
    let snapshot = await harness.assembly.snapshot()
    XCTAssertTrue(snapshot.pendingApprovals.isEmpty)

    let codes = harness.sink.entries().map(\.code)
    XCTAssertTrue(codes.contains("event.request.item/commandExecution/requestApproval"))
    XCTAssertTrue(codes.contains("command.registered.resolveApproval"))
    XCTAssertTrue(codes.contains("approval.confirmed"))
    let serialized = String(
      decoding: try JSONEncoder().encode(harness.sink.entries()),
      as: UTF8.self
    )
    XCTAssertFalse(serialized.contains("SENTINEL_COMMAND"))
    XCTAssertFalse(serialized.contains("/sentinel/private/path"))
    XCTAssertFalse(serialized.contains("thread-1"))
    await harness.shutdown()
  }

  func testSuspendAndResumeDoesNotTriggerRecovery() async throws {
    let first = FakeCodexAppServer()
    let second = FakeCodexAppServer()
    let harness = try await AssemblyHarness.start(servers: [first, second])

    await harness.assembly.suspend()
    let paused = await harness.updateLog.eventually { updates in
      updates.contains(.recovery(.runtimeState(.stopped)))
    }
    XCTAssertTrue(paused, "Expected a clean pause.")

    await harness.assembly.resume()
    let resumed = await harness.updateLog.eventually { updates in
      updates.contains(.recovery(.runtimeState(.ready(AssemblyHarness.report))))
    }
    XCTAssertTrue(resumed, "Expected the runtime to come back after resume.")

    let updates = await harness.updateLog.all()
    let recoveries = updates.filter { update in
      if case .recovery(.recoveryStarted) = update { return true }
      return false
    }
    XCTAssertTrue(
      recoveries.isEmpty,
      "A clean suspend/resume must not run degraded-state recovery."
    )
    await harness.shutdown()
  }

  func testCrashRecoveryFlowsThroughAssemblyUpdates() async throws {
    let first = FakeCodexAppServer()
    first.stubResult(
      "thread/read",
      CodexAppServerFixtures.threadReadResult(
        CodexAppServerFixtures.thread(id: "thread-1", status: "active")
      )
    )
    let second = FakeCodexAppServer()
    second.stubResult(
      "thread/read",
      CodexAppServerFixtures.threadReadResult(
        CodexAppServerFixtures.thread(id: "thread-1", status: "idle")
      )
    )
    let harness = try await AssemblyHarness.start(servers: [first, second])
    try first.emit(
      CodexAppServerFixtures.threadStatusChanged(threadID: "thread-1", status: "active"))
    _ = await harness.updateLog.eventually { updates in
      updates.contains { if case .stateChanged = $0 { return true } else { return false } }
    }

    first.crash(exitStatus: 9)
    let recovered = await harness.updateLog.eventually(timeout: .seconds(5)) { updates in
      updates.contains(
        .recovery(.rebuilt(threadIDs: ["thread-1"], droppedThreadIDs: [])))
    }
    XCTAssertTrue(recovered, "Expected recovery to rebuild through the assembly.")
    let state = await harness.assembly.runtimeState()
    XCTAssertEqual(state, .ready(AssemblyHarness.report))
    await harness.shutdown()
  }

  func testLedgerFactoryComputesApplicationSupportPathAndCreatesDatabase() async throws {
    let base = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-assembly-test-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: base) }

    let databaseURL = try BridgeLedgerFactory.applicationSupportDatabaseURL(base: base)
    XCTAssertEqual(
      databaseURL.path,
      base.appendingPathComponent("CodexMicro/command-ledger.sqlite").path
    )

    let key = SymmetricKey(data: Data(repeating: 0x61, count: 32))
    let ledger = try PersistentCommandLedger(databaseURL: databaseURL, key: key)
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(timeIntervalSince1970: 100),
      body: .interruptTurn(threadID: "thread-1", turnID: "turn-1")
    )
    _ = try await ledger.register(deviceID: UUID(), command: command, at: Date())

    XCTAssertTrue(FileManager.default.fileExists(atPath: databaseURL.path))
  }
}

// MARK: - Harness

private actor AssemblyUpdateLog {
  private var updates: [BridgeUpdate] = []

  func append(_ update: BridgeUpdate) {
    updates.append(update)
  }

  func all() -> [BridgeUpdate] {
    updates
  }

  func eventually(
    timeout: Duration = .seconds(2),
    _ condition: ([BridgeUpdate]) -> Bool
  ) async -> Bool {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
      if condition(updates) { return true }
      try? await Task.sleep(for: .milliseconds(10))
    }
    return condition(updates)
  }
}

private struct ApprovalNotIngested: Error {}

private struct AssemblyHarness {
  static let report = CodexCompatibilityReport(
    codexVersion: "0.146.0",
    schemaDigest: "expected"
  )

  let assembly: CodexBridgeAssembly
  let sink: CapturingAssemblyLogSink
  let updateLog: AssemblyUpdateLog
  let updateTask: Task<Void, Never>

  static func start(servers: [FakeCodexAppServer]) async throws -> AssemblyHarness {
    let factory = AssemblySessionFactory(
      servers.map { server in
        LiveCodexRuntimeSession(
          client: CodexAppServerClient(transport: server, timeout: .seconds(2))
        )
      }
    )
    let supervisor = CodexRuntimeSupervisor(
      policy: .init(
        supportedManifests: [
          .init(codexVersion: report.codexVersion, schemaDigest: report.schemaDigest)
        ]
      ),
      prober: FixedCompatibilityProbe(report: report),
      makeSession: { factory.next() }
    )
    let sink = CapturingAssemblyLogSink()
    let assembly = try CodexBridgeAssembly(
      supervisor: supervisor,
      ledger: InMemoryCommandLedger(),
      logger: RedactedLogger(sink: sink),
      configuration: .init(
        resolutionTimeout: .seconds(2),
        restartDelay: .milliseconds(10),
        maximumRestartDelay: .milliseconds(40)
      )
    )
    let updateLog = AssemblyUpdateLog()
    let updateTask = Task {
      for await update in assembly.updates {
        await updateLog.append(update)
      }
    }
    await assembly.start()
    let ready = await updateLog.eventually { updates in
      updates.contains(.recovery(.runtimeState(.ready(report))))
    }
    guard ready else { throw ApprovalNotIngested() }
    return AssemblyHarness(
      assembly: assembly,
      sink: sink,
      updateLog: updateLog,
      updateTask: updateTask
    )
  }

  func pendingApproval(requestID: String) async throws -> CompanionPendingApproval {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while ContinuousClock.now < deadline {
      let pending = await assembly.snapshot().pendingApprovals
      if let approval = pending.first(where: { $0.requestID == requestID }) {
        return approval
      }
      try await Task.sleep(for: .milliseconds(10))
    }
    throw ApprovalNotIngested()
  }

  func shutdown() async {
    await assembly.stop()
    updateTask.cancel()
  }
}

private final class AssemblySessionFactory: @unchecked Sendable {
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

private struct FixedCompatibilityProbe: CodexCompatibilityProbing {
  let report: CodexCompatibilityReport

  func probe() async throws -> CodexCompatibilityReport {
    report
  }
}

final class CapturingAssemblyLogSink: RedactedLogSink, @unchecked Sendable {
  private let lock = NSLock()
  private var captured: [RedactedLogEntry] = []

  func write(_ entry: RedactedLogEntry) {
    lock.lock()
    captured.append(entry)
    lock.unlock()
  }

  func entries() -> [RedactedLogEntry] {
    lock.lock()
    defer { lock.unlock() }
    return captured
  }
}
