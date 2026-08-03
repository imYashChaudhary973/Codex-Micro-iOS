import CodexAppServer
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Step 2.9's two P0 semantic mutations: `interruptTurn`, which may call
/// Codex at most once across duplicates and reconnects, and `markThreadRead`,
/// which is device-own, scoped, monotonic, and never calls Codex.
final class GatewayP0CommandTests: XCTestCase {
  private static let now = Date(timeIntervalSince1970: 1_000_000)
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
  private let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
  private let commandID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!

  // MARK: - interruptTurn

  func testInterruptCallsCodexExactlyOnceAndSucceeds() async throws {
    let world = try await World()

    let outcome = await world.execute(try interruptCommand())

    guard case .completed(let record) = outcome else { return XCTFail("expected completion") }
    XCTAssertEqual(record.state, .succeeded)
    XCTAssertEqual(record.resultCode, .completed)
    XCTAssertEqual(record.threadID, "thread-a")
    XCTAssertEqual(record.turnID, "turn-1")
    let calls = await world.responder.interruptCalls
    XCTAssertEqual(calls.count, 1)
    XCTAssertEqual(calls.first?.threadID, "thread-a")
    XCTAssertEqual(calls.first?.turnID, "turn-1")
  }

  func testDuplicateInterruptsProduceExactlyOneExternalCall() async throws {
    let world = try await World()
    let command = try interruptCommand()

    for _ in 0..<5 {
      _ = await world.execute(command)
    }

    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 1)
  }

  func testInterruptAcrossAReconnectProducesOneExternalCall() async throws {
    let world = try await World()
    let command = try interruptCommand()
    _ = await world.execute(command)

    // The device reconnects: a new session, and the same command re-issued
    // with a fresh timestamp.
    let reconnected = UUID()
    world.sessions.register(deviceID: deviceID, sessionID: reconnected)
    let retry = try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now.addingTimeInterval(20),
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-1")
    )
    let outcome = await world.gateway.execute(
      command: retry,
      context: NetworkCommandContext(deviceID: deviceID, sessionID: reconnected),
      now: Self.now.addingTimeInterval(20)
    )

    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 1)
    guard case .replayed(let record) = outcome else { return XCTFail("expected a replay") }
    XCTAssertEqual(record.state, .succeeded)
  }

  func testAFailedInterruptIsTerminalAndNeverResent() async throws {
    let world = try await World()
    await world.responder.setFailure(CodexRuntimeRequestError.notReady)
    let command = try interruptCommand()

    let first = await world.execute(command)
    guard case .outcomeUnknown(let record) = first else {
      return XCTFail("a failed external call must be outcomeUnknown")
    }
    XCTAssertEqual(record.resultCode, .codexUnavailable)

    await world.responder.setFailure(nil)
    let second = await world.execute(command)

    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 1, "the command must never be resent")
    guard case .outcomeUnknown = second else {
      return XCTFail("the ambiguous outcome must persist")
    }
  }

  func testInterruptWithoutTheCapabilityMakesNoExternalCall() async throws {
    let world = try await World(capabilities: [.view])

    let outcome = await world.execute(try interruptCommand())

    XCTAssertEqual(outcome, .denied(.capabilityMissing))
    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 0)
  }

  func testInterruptOutsideProjectScopeMakesNoExternalCall() async throws {
    let world = try await World(projects: ["project-b"])

    let outcome = await world.execute(try interruptCommand())

    XCTAssertEqual(outcome, .denied(.projectNotAllowed))
    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 0)
  }

  func testADegradedRuntimeMakesNoExternalCall() async throws {
    let world = try await World()
    world.runtime.setReady(false)

    let outcome = await world.execute(try interruptCommand())

    XCTAssertEqual(outcome, .denied(.runtimeUnavailable))
    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 0)
  }

  /// The crash boundary *before* the external call: a claim exists but the
  /// call never happened. The retry must not make the call either — the
  /// bridge cannot tell the two boundaries apart.
  func testACrashBetweenClaimAndCallResolvesToOutcomeUnknown() async throws {
    let world = try await World()
    let command = try interruptCommand()
    _ = try await world.ledger.claim(
      deviceID: deviceID,
      commandID: command.commandID,
      kind: .interruptTurn,
      semanticDigest: SemanticCommandDigest.digest(
        of: command, projectID: "project-a", effectiveProfile: .observe),
      at: Self.now
    )

    let outcome = await world.execute(command)

    guard case .outcomeUnknown(let record) = outcome else {
      return XCTFail("expected outcomeUnknown")
    }
    XCTAssertEqual(record.resultCode, .bridgeRestartedBeforeOutcome)
    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 0)
  }

  /// The crash boundary *after* the external call: the ledger says
  /// `submitted` and the call did happen. It is equally never resent.
  func testACrashAfterTheCallResolvesToOutcomeUnknownWithoutResending() async throws {
    let world = try await World()
    let command = try interruptCommand()
    _ = try await world.ledger.claim(
      deviceID: deviceID,
      commandID: command.commandID,
      kind: .interruptTurn,
      semanticDigest: SemanticCommandDigest.digest(
        of: command, projectID: "project-a", effectiveProfile: .observe),
      at: Self.now
    )
    try await world.ledger.markSubmitted(
      commandID: command.commandID, threadID: "thread-a", turnID: "turn-1", requestID: nil,
      at: Self.now)

    let outcome = await world.execute(command)

    guard case .outcomeUnknown = outcome else { return XCTFail("expected outcomeUnknown") }
    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 0)
  }

  // MARK: - markThreadRead

  func testMarkThreadReadAdvancesTheCursorWithoutCallingCodex() async throws {
    let world = try await World()

    let outcome = await world.execute(try markReadCommand(through: 4))

    guard case .completed(let record) = outcome else { return XCTFail("expected completion") }
    XCTAssertEqual(record.state, .succeeded)
    let cursor = try await world.readCursors.cursor(deviceID: deviceID, threadID: "thread-a")
    XCTAssertEqual(cursor?.readSequence, 4)
    let count = await world.responder.interruptCallCount
    XCTAssertEqual(count, 0)
  }

  func testMarkThreadReadIsMonotonicAndARegressionIsDenied() async throws {
    let world = try await World()
    _ = await world.execute(try markReadCommand(through: 9, commandID: UUID()))

    let outcome = await world.execute(try markReadCommand(through: 4, commandID: UUID()))

    XCTAssertEqual(outcome, .denied(.staleCommand))
    let cursor = try await world.readCursors.cursor(deviceID: deviceID, threadID: "thread-a")
    XCTAssertEqual(cursor?.readSequence, 9, "a denied regression must not move the cursor")
  }

  func testAReplayedMarkThreadReadCannotUnreadAThread() async throws {
    let world = try await World()
    let command = try markReadCommand(through: 6)
    _ = await world.execute(command)
    _ = await world.execute(try markReadCommand(through: 9, commandID: UUID()))

    // The same command arrives again after the cursor has moved on.
    let replayed = await world.execute(command)

    guard case .replayed = replayed else { return XCTFail("expected a replay") }
    let cursor = try await world.readCursors.cursor(deviceID: deviceID, threadID: "thread-a")
    XCTAssertEqual(cursor?.readSequence, 9)
  }

  func testMarkThreadReadIsScopedToThePermittedProjects() async throws {
    let world = try await World(projects: ["project-a"])

    let outcome = await world.execute(
      try ClientCommand(
        commandID: commandID,
        issuedAt: Self.now,
        body: .markThreadRead(threadID: "thread-b", throughSequence: 2)
      )
    )

    XCTAssertEqual(outcome, .denied(.projectNotAllowed))
  }

  func testMarkThreadReadIsDeviceOwn() async throws {
    let world = try await World()
    try await world.addSecondDevice()
    _ = await world.execute(try markReadCommand(through: 7))

    let foreign = try await world.readCursors.cursor(
      deviceID: otherDeviceID, threadID: "thread-a")

    XCTAssertNil(foreign)
  }

  func testMarkThreadReadRequiresTheViewCapability() async throws {
    let world = try await World(capabilities: [.interrupt])

    let outcome = await world.execute(try markReadCommand(through: 3))

    XCTAssertEqual(outcome, .denied(.capabilityMissing))
  }

  func testTwoDevicesKeepIndependentReadPositions() async throws {
    let world = try await World()
    try await world.addSecondDevice()

    _ = await world.execute(try markReadCommand(through: 5))
    _ = await world.gateway.execute(
      command: try markReadCommand(through: 2, commandID: UUID()),
      context: NetworkCommandContext(deviceID: otherDeviceID, sessionID: world.otherSessionID),
      now: Self.now
    )

    let first = try await world.readCursors.cursor(deviceID: deviceID, threadID: "thread-a")
    let second = try await world.readCursors.cursor(deviceID: otherDeviceID, threadID: "thread-a")
    XCTAssertEqual(first?.readSequence, 5)
    XCTAssertEqual(second?.readSequence, 2)
  }

  // MARK: - Fixtures

  private func interruptCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now,
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-1")
    )
  }

  private func markReadCommand(through: UInt64, commandID: UUID? = nil) throws -> ClientCommand {
    try ClientCommand(
      commandID: commandID ?? self.commandID,
      issuedAt: Self.now,
      body: .markThreadRead(threadID: "thread-a", throughSequence: through)
    )
  }

  private struct World {
    let authority: DeviceGrantAuthority
    let gateway: NetworkCommandGateway
    let ledger: InMemoryCommandLedger
    let sessions: FakeNetworkSessionVerifier
    let runtime = FakeNetworkRuntime()
    let responder = FakeCommandResponder()
    let turnStarter = FakeTurnStarter()
    let turnSteerer = FakeTurnSteerer()
    let turnPolicies = TurnPolicyRegistry()
    let workspaceRoots = FakeWorkspaceRootResolver()
    let readCursors: DeviceReadCursorStore
    let table = ThreadProjectTable()
    let context: NetworkCommandContext
    let otherSessionID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
    private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
    private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!

    init(
      projects: Set<String> = ["project-a"],
      capabilities: Set<DeviceCapability> = [.view, .interrupt]
    ) async throws {
      let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
      authority = DeviceGrantAuthority(
        storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
      _ = try await authority.addGrant(
        deviceID: deviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: capabilities,
        permittedProjectIDs: projects
      )
      table.attribute(threadID: "thread-a", projectID: "project-a")
      table.attribute(threadID: "thread-b", projectID: "project-b")
      sessions = FakeNetworkSessionVerifier(deviceID: deviceID, sessionID: sessionID)
      ledger = InMemoryCommandLedger()
      readCursors = try DeviceReadCursorStore(
        storage: InMemoryReadCursorStorage(),
        scopes: authority,
        attribution: table,
        clock: { 1_000_000 }
      )
      context = NetworkCommandContext(deviceID: deviceID, sessionID: sessionID)
      gateway = NetworkCommandGateway(
        authority: authority,
        attribution: table,
        ledger: ledger,
        sessions: sessions,
        runtime: runtime,
        responder: responder,
        turnStarter: turnStarter,
        turnSteerer: turnSteerer,
        turnPolicies: turnPolicies,
        workspaceRoots: workspaceRoots,
        readCursors: readCursors
      )
    }

    func execute(_ command: ClientCommand) async -> NetworkCommandOutcome {
      await gateway.execute(
        command: command, context: context, now: Date(timeIntervalSince1970: 1_000_000))
    }

    func addSecondDevice() async throws {
      _ = try await authority.addGrant(
        deviceID: otherDeviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: [.view, .interrupt],
        permittedProjectIDs: ["project-a"]
      )
      sessions.register(deviceID: otherDeviceID, sessionID: otherSessionID)
    }
  }
}
