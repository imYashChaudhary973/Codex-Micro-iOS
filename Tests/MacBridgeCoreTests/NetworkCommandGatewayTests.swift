import CodexAppServer
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Deterministic session verifier.
final class FakeNetworkSessionVerifier: NetworkSessionVerifying, @unchecked Sendable {
  private let lock = NSLock()
  private var current: [UUID: UUID] = [:]

  init(deviceID: UUID? = nil, sessionID: UUID? = nil) {
    if let deviceID, let sessionID { current[deviceID] = sessionID }
  }

  func isCurrentSession(deviceID: UUID, sessionID: UUID) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return current[deviceID] == sessionID
  }

  func register(deviceID: UUID, sessionID: UUID) {
    lock.lock()
    defer { lock.unlock() }
    current[deviceID] = sessionID
  }

  func invalidate() {
    lock.lock()
    defer { lock.unlock() }
    current.removeAll()
  }
}

/// Deterministic Codex responder that counts every external call.
actor FakeCommandResponder: CodexApprovalResponding {
  private(set) var interruptCalls: [(threadID: String, turnID: String)] = []
  private var failure: (any Error)?

  func setFailure(_ error: (any Error)?) { failure = error }

  var interruptCallCount: Int { interruptCalls.count }

  func respondToServerRequest(id: Int64, result: JSONValue) async throws {}

  func interruptTurn(threadID: String, turnID: String) async throws {
    interruptCalls.append((threadID, turnID))
    if let failure { throw failure }
  }
}

/// Deterministic turn starter that records every phone-originated turn.
actor FakeTurnStarter: CodexTurnStarting {
  private(set) var started: [(threadID: String, prompt: String, policy: PhoneTurnPolicy)] = []
  private var failure: (any Error)?
  private var nextTurnID = "turn-started-1"

  func setFailure(_ error: (any Error)?) { failure = error }
  func setNextTurnID(_ value: String) { nextTurnID = value }

  var startCount: Int { started.count }

  func startTurn(
    threadID: String,
    prompt: String,
    policy: PhoneTurnPolicy
  ) async throws -> String {
    started.append((threadID, prompt, policy))
    if let failure { throw failure }
    return nextTurnID
  }
}

/// Deterministic turn steerer that records every steer.
actor FakeTurnSteerer: CodexTurnSteering {
  private(set) var steered: [(threadID: String, turnID: String, prompt: String)] = []
  private var failure: (any Error)?

  func setFailure(_ error: (any Error)?) { failure = error }

  var steerCount: Int { steered.count }

  func steerTurn(threadID: String, turnID: String, prompt: String) async throws {
    steered.append((threadID, turnID, prompt))
    if let failure { throw failure }
  }
}

/// Deterministic writable-root source.
final class FakeWorkspaceRootResolver: WorkspaceRootResolving, @unchecked Sendable {
  private let lock = NSLock()
  private var roots: [String: [String]] = [:]

  func writableRoots(forProjectID projectID: String) -> [String] {
    lock.lock()
    defer { lock.unlock() }
    return roots[projectID] ?? []
  }

  func setRoots(_ values: [String], for projectID: String) {
    lock.lock()
    defer { lock.unlock() }
    roots[projectID] = values
  }
}

/// Deterministic runtime readiness.
final class FakeNetworkRuntime: NetworkRuntimeReadiness, @unchecked Sendable {
  private let lock = NSLock()
  private var ready: Bool

  init(ready: Bool = true) { self.ready = ready }

  func isReadyForStateChange() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return ready
  }

  func setReady(_ value: Bool) {
    lock.lock()
    defer { lock.unlock() }
    ready = value
  }
}

/// A ledger that fails every claim, proving ledger failure denies new
/// state-changing commands (plan §2 invariant 15).
actor FailingClaimLedger: CommandLedgering {
  func register(deviceID: UUID, command: ClientCommand, at date: Date) throws
    -> CommandRegistration
  {
    throw CommandLedgerError.missingCommand
  }

  func claim(
    deviceID: UUID,
    commandID: UUID,
    kind: CompanionCommandKind,
    semanticDigest: String,
    at date: Date
  ) throws -> NetworkCommandClaim {
    throw CommandLedgerError.missingCommand
  }

  func markSubmitted(
    commandID: UUID, threadID: String?, turnID: String?, requestID: String?, at date: Date
  ) throws {}
  func finish(
    commandID: UUID, state: CommandLifecycleState, resultCode: CommandResultCode, at date: Date
  ) throws {}
  func markOutcomeUnknown(commandID: UUID, resultCode: CommandResultCode, at date: Date) throws {}
  func markInFlightOutcomesUnknown(at date: Date) throws {}
  func record(commandID: UUID) -> CommandLedgerRecord? { nil }
}

/// Step 2.9 gateway contracts: the fixed check order, device-bound command
/// identity, and known-result replay.
final class NetworkCommandGatewayTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
  private let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
  private let commandID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!

  // MARK: - Closed surfaces

  func testApprovalsAreRejectedForAllOfPhaseTwo() async throws {
    let world = try await World()
    let command = try approvalCommand()

    let outcome = await world.gateway.execute(command: command, context: world.context)

    XCTAssertEqual(outcome, .denied(.approvalsUnsupported))
    let record = await world.ledger.record(commandID: command.commandID)
    XCTAssertNil(record)
  }

  func testNonemptyAttachmentsAreRejected() async throws {
    let world = try await World()
    let command = try ClientCommand(
      commandID: commandID,
      issuedAt: World.now,
      body: .sendPrompt(threadID: "thread-a", prompt: "hi", attachmentIDs: ["attachment-1"])
    )

    let outcome = await world.gateway.execute(command: command, context: world.context)

    XCTAssertEqual(outcome, .denied(.attachmentsUnsupported))
  }

  func testEveryCommandOutsideTheAllowlistIsRejected() async throws {
    let world = try await World()
    let bodies: [ClientCommandBody] = [
      .selectThread(threadID: "thread-a"),
      .startThread(projectID: "project-a", prompt: "hi", attachmentIDs: []),
    ]

    for body in bodies {
      let command = try ClientCommand(commandID: UUID(), issuedAt: World.now, body: body)
      let outcome = await world.gateway.execute(command: command, context: world.context)
      XCTAssertEqual(outcome, .denied(.unsupportedCommand), "\(body.kind)")
    }
  }

  func testTheAllowlistIsExactlyTheEnabledMutations() {
    XCTAssertEqual(
      NetworkCommandGateway.allowedCommandKinds,
      [.interruptTurn, .markThreadRead, .sendPrompt, .steerTurn]
    )
  }

  /// Step 2.12 was closed by a recorded product decision: v1 is
  /// read/respond/control-only and the phone may not create threads.
  ///
  /// This test is the enforcement of that decision, not a restatement of it.
  /// `startThread` must stay off the allowlist and must stay denied for a
  /// grant that carries the `.startThread` capability and every profile —
  /// so adding it back requires deliberately deleting this test, which is
  /// exactly the moment the decision should be revisited.
  func testStartThreadStaysClosedByTheRecordedStepTwelveDeferral() async throws {
    XCTAssertFalse(NetworkCommandGateway.allowedCommandKinds.contains(.startThread))

    for profile in MobileActionProfile.allCases {
      let world = try await World(
        capabilities: Set(DeviceCapability.allCases), profile: profile)
      let command = try ClientCommand(
        commandID: UUID(),
        issuedAt: World.now,
        body: .startThread(projectID: "project-a", prompt: "hi", attachmentIDs: [])
      )

      let outcome = await world.gateway.execute(command: command, context: world.context)

      XCTAssertEqual(outcome, .denied(.unsupportedCommand), "\(profile)")
      let record = await world.ledger.record(commandID: command.commandID)
      XCTAssertNil(record, "a refused startThread must leave no ledger record")
      let starts = await world.turnStarter.startCount
      XCTAssertEqual(starts, 0)
    }
  }

  /// Both agent commands are on the allowlist but gated a second time by the
  /// grant. The Step 2.9 fixture's grant has no `.runAgent`, so they are
  /// still denied — just for the right reason.
  func testAgentCommandsAreAllowlistedButStillNeedTheRunAgentGrant() async throws {
    let world = try await World()
    let bodies: [ClientCommandBody] = [
      .sendPrompt(threadID: "thread-a", prompt: "hi", attachmentIDs: []),
      .steerTurn(threadID: "thread-a", turnID: "turn-1", prompt: "hi"),
    ]

    for body in bodies {
      let command = try ClientCommand(commandID: UUID(), issuedAt: World.now, body: body)
      let outcome = await world.gateway.execute(command: command, context: world.context)
      XCTAssertEqual(outcome, .denied(.capabilityMissing), "\(body.kind)")
    }
  }

  func testClosedSurfacesAreRejectedBeforeAnyLedgerClaimExists() async throws {
    let world = try await World()

    for command in [try approvalCommand(), try attachmentCommand()] {
      _ = await world.gateway.execute(command: command, context: world.context)
      let record = await world.ledger.record(commandID: command.commandID)
      XCTAssertNil(record, "\(command.body.kind) left a ledger record")
    }
  }

  // MARK: - Session and authority

  func testAStaleSessionIsDenied() async throws {
    let world = try await World()
    world.sessions.invalidate()

    let outcome = await world.gateway.execute(
      command: try interruptCommand(), context: world.context)

    XCTAssertEqual(outcome, .denied(.revokedDevice))
  }

  func testASessionIdentifierFromAnotherDeviceIsDenied() async throws {
    let world = try await World()
    let foreign = NetworkCommandContext(deviceID: otherDeviceID, sessionID: sessionID)

    let outcome = await world.gateway.execute(command: try interruptCommand(), context: foreign)

    XCTAssertEqual(outcome, .denied(.revokedDevice))
  }

  func testARevokedDeviceIsDeniedEvenWithAValidSession() async throws {
    let world = try await World()
    _ = try await world.authority.revoke(deviceID: deviceID)

    let outcome = await world.gateway.execute(
      command: try interruptCommand(), context: world.context)

    XCTAssertEqual(outcome, .denied(.revokedDevice))
  }

  func testAnUnavailableAuthorityDeniesOutright() async throws {
    let world = try await World()
    world.storage.failLoads(with: .storageUnavailable)
    try? await world.authority.reloadFromStore()

    let outcome = await world.gateway.execute(
      command: try interruptCommand(), context: world.context)

    XCTAssertEqual(outcome, .denied(.ledgerUnavailable))
  }

  func testLedgerFailureDeniesNewStateChangingCommands() async throws {
    let world = try await World(ledger: FailingClaimLedger())

    let outcome = await world.gateway.execute(
      command: try interruptCommand(), context: world.context)

    XCTAssertEqual(outcome, .denied(.ledgerUnavailable))
  }

  // MARK: - Policy checks

  func testACommandOutsideTheProjectScopeIsDenied() async throws {
    let world = try await World(projects: ["project-b"])

    let outcome = await world.gateway.execute(
      command: try interruptCommand(), context: world.context)

    XCTAssertEqual(outcome, .denied(.projectNotAllowed))
  }

  func testAnUnattributedThreadHasNoProjectContext() async throws {
    let world = try await World()
    let command = try ClientCommand(
      commandID: commandID,
      issuedAt: World.now,
      body: .interruptTurn(threadID: "thread-unattributed", turnID: "turn-1")
    )

    let outcome = await world.gateway.execute(command: command, context: world.context)

    XCTAssertEqual(outcome, .denied(.projectNotAllowed))
  }

  func testAMissingCapabilityIsDenied() async throws {
    let world = try await World(capabilities: [.view])

    let outcome = await world.gateway.execute(
      command: try interruptCommand(), context: world.context)

    XCTAssertEqual(outcome, .denied(.capabilityMissing))
  }

  func testAStaleCommandIsDenied() async throws {
    let world = try await World()
    let command = try ClientCommand(
      commandID: commandID,
      issuedAt: World.now.addingTimeInterval(-3_600),
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-1")
    )

    let outcome = await world.gateway.execute(command: command, context: world.context)

    XCTAssertEqual(outcome, .denied(.staleCommand))
  }

  func testADegradedRuntimeDeniesACommandThatWouldReachCodex() async throws {
    let world = try await World()
    world.runtime.setReady(false)

    let outcome = await world.gateway.execute(
      command: try interruptCommand(), context: world.context)

    XCTAssertEqual(outcome, .denied(.runtimeUnavailable))
  }

  func testADegradedRuntimeDoesNotDenyADeviceLocalMutation() async throws {
    let world = try await World()
    world.runtime.setReady(false)

    let outcome = await world.gateway.execute(
      command: try markReadCommand(), context: world.context)

    guard case .completed = outcome else {
      return XCTFail("a device-local mutation must not depend on the runtime")
    }
  }

  /// A denied command must leave **no** ledger record. Otherwise an honest
  /// retry after the runtime recovers would find its own denied claim and
  /// resolve to `outcomeUnknown` instead of executing.
  func testADeniedCommandIsNeverQueuedAndLeavesNoClaim() async throws {
    let world = try await World()
    world.runtime.setReady(false)
    let command = try interruptCommand()

    let denied = await world.gateway.execute(command: command, context: world.context)

    XCTAssertEqual(denied, .denied(.runtimeUnavailable))
    let afterDenial = await world.ledger.record(commandID: command.commandID)
    XCTAssertNil(afterDenial)

    world.runtime.setReady(true)
    let retried = await world.gateway.execute(command: command, context: world.context)
    XCTAssertNotEqual(retried, .denied(.runtimeUnavailable))
    guard case .outcomeUnknown = retried else { return }
    XCTFail("a retry after recovery must not resolve to outcomeUnknown")
  }

  // MARK: - Device-bound command identity

  func testReusingACommandIdentifierWithADifferentPayloadFailsClosed() async throws {
    let world = try await World()
    try await world.recordTerminalResult(for: try interruptCommand())

    let collided = try ClientCommand(
      commandID: commandID,
      issuedAt: World.now,
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-DIFFERENT")
    )
    let outcome = await world.gateway.execute(command: collided, context: world.context)

    XCTAssertEqual(outcome, .denied(.duplicateMismatch))
  }

  func testAnotherDeviceCannotReuseACommandIdentifier() async throws {
    let world = try await World()
    try await world.recordTerminalResult(for: try interruptCommand())
    try await world.addSecondDevice()

    let outcome = await world.gateway.execute(
      command: try interruptCommand(),
      context: NetworkCommandContext(deviceID: otherDeviceID, sessionID: world.otherSessionID)
    )

    XCTAssertEqual(outcome, .denied(.duplicateMismatch))
  }

  func testAnHonestRetryAfterAReconnectIsNotACollision() async throws {
    let world = try await World()
    try await world.recordTerminalResult(for: try interruptCommand())

    // Same command, re-issued later with a fresh timestamp, as a device that
    // retries across a reconnect would send it.
    let retry = try ClientCommand(
      commandID: commandID,
      issuedAt: World.now.addingTimeInterval(5),
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-1")
    )
    let outcome = await world.gateway.execute(command: retry, context: world.context)

    XCTAssertNotEqual(outcome, .denied(.duplicateMismatch))
  }

  // MARK: - Known result before new execution

  func testAKnownTerminalResultReplaysWithoutExecuting() async throws {
    let world = try await World()
    let command = try interruptCommand()
    try await world.recordTerminalResult(for: command)

    let outcome = await world.gateway.execute(command: command, context: world.context)

    guard case .replayed(let record) = outcome else { return XCTFail("expected a replay") }
    XCTAssertEqual(record.state, .succeeded)
  }

  func testAKnownResultReplaysEvenWhenStaleAndDegraded() async throws {
    let world = try await World()
    let command = try interruptCommand()
    try await world.recordTerminalResult(for: command)
    world.runtime.setReady(false)

    let stale = try ClientCommand(
      commandID: commandID,
      issuedAt: World.now.addingTimeInterval(-3_600),
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-1")
    )
    let outcome = await world.gateway.execute(command: stale, context: world.context)

    guard case .replayed = outcome else {
      return XCTFail("a known result must replay past freshness and degradation")
    }
  }

  func testAKnownResultIsWithheldWhenDisclosureIsNoLongerAuthorized() async throws {
    let world = try await World(projects: ["project-a", "project-b"])
    let command = try interruptCommand()
    try await world.recordTerminalResult(for: command)

    _ = try await world.authority.reduceScope(
      deviceID: deviceID, permittedProjectIDs: ["project-b"])

    let outcome = await world.gateway.execute(command: command, context: world.context)

    XCTAssertEqual(outcome, .denied(.projectNotAllowed))
  }

  func testACrashAmbiguousClaimBecomesOutcomeUnknownAndIsNeverResent() async throws {
    let world = try await World()
    let command = try markReadCommand()
    // A claim that never reached a terminal state: the bridge stopped between
    // claiming and finishing.
    _ = try await world.ledger.claim(
      deviceID: deviceID,
      commandID: command.commandID,
      kind: .markThreadRead,
      semanticDigest: SemanticCommandDigest.digest(
        of: command, projectID: "project-a", effectiveProfile: .observe),
      at: World.now
    )

    let outcome = await world.gateway.execute(command: command, context: world.context)

    guard case .outcomeUnknown(let record) = outcome else {
      return XCTFail("expected outcomeUnknown")
    }
    XCTAssertEqual(record.state, .outcomeUnknown)
    XCTAssertEqual(record.resultCode, .bridgeRestartedBeforeOutcome)
  }

  // MARK: - Wire mapping

  func testEveryOutcomeMapsOntoTheClosedWireVocabulary() throws {
    let record = try sampleRecord()
    let cases: [(NetworkCommandOutcome, SecureCommandOutcome)] = [
      (.completed(record), .completed),
      (.replayed(record), .completed),
      (.outcomeUnknown(record), .outcomeUnknown),
      (.failed(record), .failed),
      (.denied(.revokedDevice), .denied),
    ]

    for (outcome, expected) in cases {
      let result = try outcome.wireResult(commandID: commandID)
      XCTAssertEqual(result.outcome, expected)
      XCTAssertEqual(result.commandID, commandID)
      XCTAssertEqual(result.denialReason != nil, expected == .denied)
    }
  }

  func testEveryPolicyDenialHasAClosedWireReason() {
    let reasons: [CommandDenialReason] = [
      .revokedDevice, .missingCapability, .projectNotAllowed, .missingProjectContext,
      .actionProfileTooRestrictive, .staleCommand,
    ]

    let mapped = reasons.map(NetworkCommandGateway.wireReason)

    XCTAssertEqual(Set(mapped).count, 5)
    XCTAssertTrue(mapped.allSatisfy { SecureCommandDenialReason.allCases.contains($0) })
  }

  // MARK: - Fixtures

  private func interruptCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: commandID,
      issuedAt: World.now,
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-1")
    )
  }

  private func markReadCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: commandID,
      issuedAt: World.now,
      body: .markThreadRead(threadID: "thread-a", throughSequence: 4)
    )
  }

  private func approvalCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: UUID(),
      issuedAt: World.now,
      body: .resolveApproval(
        requestID: "request-1",
        decision: .approveOnce,
        requestDigest: String(repeating: "a", count: 64)
      )
    )
  }

  private func attachmentCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: UUID(),
      issuedAt: World.now,
      body: .sendPrompt(threadID: "thread-a", prompt: "hi", attachmentIDs: ["attachment-1"])
    )
  }

  private func sampleRecord() throws -> CommandLedgerRecord {
    CommandLedgerRecord(
      commandID: commandID,
      deviceID: deviceID,
      commandKind: .interruptTurn,
      requestDigest: String(repeating: "0", count: 64),
      state: .succeeded,
      createdAt: World.now,
      updatedAt: World.now
    )
  }

  private struct World {
    static let now = Date(timeIntervalSince1970: 1_000_000)

    let authority: DeviceGrantAuthority
    let gateway: NetworkCommandGateway
    let ledger: any CommandLedgering
    let sessions: FakeNetworkSessionVerifier
    let runtime = FakeNetworkRuntime()
    let table = ThreadProjectTable()
    let storage = InMemoryGrantAuthorityStore()
    let responder = FakeCommandResponder()
    let turnStarter = FakeTurnStarter()
    let turnSteerer = FakeTurnSteerer()
    let turnPolicies = TurnPolicyRegistry()
    let workspaceRoots = FakeWorkspaceRootResolver()
    let readCursors: DeviceReadCursorStore
    let context: NetworkCommandContext
    let otherSessionID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
    private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
    private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!

    init(
      projects: Set<String> = ["project-a"],
      capabilities: Set<DeviceCapability> = [.view, .interrupt],
      profile: MobileActionProfile = .observe,
      ledger: (any CommandLedgering)? = nil
    ) async throws {
      let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
      authority = DeviceGrantAuthority(storage: storage, clock: { 1_000_000 })
      _ = try await authority.addGrant(
        deviceID: deviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: capabilities,
        permittedProjectIDs: projects,
        actionProfileCeiling: profile
      )
      table.attribute(threadID: "thread-a", projectID: "project-a")
      table.attribute(threadID: "thread-b", projectID: "project-b")
      sessions = FakeNetworkSessionVerifier(deviceID: deviceID, sessionID: sessionID)
      self.ledger = ledger ?? InMemoryCommandLedger()
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
        ledger: self.ledger,
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

    func addSecondDevice() async throws {
      _ = try await authority.addGrant(
        deviceID: otherDeviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: [.view, .interrupt],
        permittedProjectIDs: ["project-a"]
      )
      sessions.register(deviceID: otherDeviceID, sessionID: otherSessionID)
    }

    /// Records a terminal result for a command without running it through the
    /// gateway, so replay behaviour is set up independently of execution.
    func recordTerminalResult(
      for command: ClientCommand,
      projectID: String? = "project-a",
      effectiveProfile: MobileActionProfile = .observe,
      state: CommandLifecycleState = .succeeded
    ) async throws {
      _ = try await ledger.claim(
        deviceID: deviceID,
        commandID: command.commandID,
        kind: command.body.kind,
        semanticDigest: SemanticCommandDigest.digest(
          of: command, projectID: projectID, effectiveProfile: effectiveProfile),
        at: World.now
      )
      try await ledger.finish(
        commandID: command.commandID, state: state, resultCode: .completed, at: World.now)
    }
  }
}

extension NetworkCommandGateway {
  /// Convenience for tests: the fixture clock is fixed, so every call uses it.
  fileprivate func execute(
    command: ClientCommand,
    context: NetworkCommandContext
  ) async -> NetworkCommandOutcome {
    await execute(command: command, context: context, now: Date(timeIntervalSince1970: 1_000_000))
  }
}
