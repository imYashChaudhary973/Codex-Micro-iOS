import CodexAppServer
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Step 2.11 `steerTurn`: the one command whose authorization depends on
/// something other than the device — the turn's own recorded effective
/// policy. A turn running more permissively than the device's current profile
/// cannot be steered by it, and a turn the bridge cannot prove anything about
/// cannot be steered at all.
final class GatewaySteerTurnTests: XCTestCase {
  private static let now = Date(timeIntervalSince1970: 1_000_000)
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
  private let commandID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!

  // MARK: - The registry's decision rule

  func testAnUnrecordedTurnCannotBeProvenAndIsRefused() async {
    let registry = TurnPolicyRegistry()

    let decision = await registry.authorizeSteering(
      threadID: "thread-a", turnID: "turn-1", deviceEffectiveProfile: .runWorkspace)

    guard case .failure(let refusal) = decision else { return XCTFail("expected a refusal") }
    XCTAssertEqual(refusal, .policyUnknown)
  }

  func testABroaderTurnPolicyIsRefusedAndAnEqualOrNarrowerOneIsAllowed() async throws {
    let registry = TurnPolicyRegistry()
    await registry.record(recorded(profile: .runWorkspace))

    let broader = await registry.authorizeSteering(
      threadID: "thread-a", turnID: "turn-1", deviceEffectiveProfile: .runReadOnly)
    guard case .failure(let refusal) = broader else { return XCTFail("expected a refusal") }
    XCTAssertEqual(refusal, .policyBroaderThanDevice)

    let equal = await registry.authorizeSteering(
      threadID: "thread-a", turnID: "turn-1", deviceEffectiveProfile: .runWorkspace)
    guard case .success = equal else { return XCTFail("an equal policy must be steerable") }

    await registry.record(recorded(profile: .runReadOnly))
    let narrower = await registry.authorizeSteering(
      threadID: "thread-a", turnID: "turn-1", deviceEffectiveProfile: .runWorkspace)
    guard case .success = narrower else { return XCTFail("a narrower policy must be steerable") }
  }

  func testTheRegistryIsBoundedAndEvictedTurnsBecomeUnprovable() async {
    let registry = TurnPolicyRegistry(capacity: 2)

    for index in 1...3 {
      await registry.record(recorded(turnID: "turn-\(index)", profile: .runReadOnly))
    }

    let count = await registry.trackedTurnCount
    XCTAssertEqual(count, 2)
    let evicted = await registry.authorizeSteering(
      threadID: "thread-a", turnID: "turn-1", deviceEffectiveProfile: .runWorkspace)
    guard case .failure(let refusal) = evicted else {
      return XCTFail("an evicted turn must be unprovable")
    }
    XCTAssertEqual(refusal, .policyUnknown)
  }

  func testRecordingTheSameTurnTwiceReplacesRatherThanGrows() async {
    let registry = TurnPolicyRegistry()

    await registry.record(recorded(profile: .runReadOnly))
    await registry.record(recorded(profile: .runWorkspace))

    let count = await registry.trackedTurnCount
    XCTAssertEqual(count, 1)
    let stored = await registry.policy(threadID: "thread-a", turnID: "turn-1")
    XCTAssertEqual(stored?.effectiveProfile, .runWorkspace)
  }

  // MARK: - Through the gateway

  func testATurnStartedByThisBridgeIsSteerable() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())

    let outcome = await world.execute(try steerCommand())

    guard case .completed(let record) = outcome else { return XCTFail("expected completion") }
    XCTAssertEqual(record.turnID, "turn-1")
    let steered = await world.turnSteerer.steered
    XCTAssertEqual(steered.count, 1)
    XCTAssertEqual(steered.first?.threadID, "thread-a")
    XCTAssertEqual(steered.first?.turnID, "turn-1")
    XCTAssertEqual(steered.first?.prompt, "steer it")
  }

  func testATurnThisBridgeNeverStartedIsRefusedWithNoExternalCall() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runWorkspace)

    let outcome = await world.execute(try steerCommand())

    XCTAssertEqual(outcome, .denied(.actionProfileTooRestrictive))
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 0)
  }

  /// The turn ran under workspace-write; the device's grant has since been
  /// narrowed to read-only. Steering must be refused even though the same
  /// device started the turn.
  func testATurnBroaderThanTheDevicesCurrentProfileIsRefused() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runWorkspace)
    world.workspaceRoots.setRoots(["/Users/example/project-a"], for: "project-a")
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())

    _ = try await world.authority.amendCapabilities(
      deviceID: deviceID,
      capabilities: [.view, .runAgent],
      actionProfileCeiling: .runReadOnly
    )

    let outcome = await world.execute(try steerCommand())

    XCTAssertEqual(outcome, .denied(.actionProfileTooRestrictive))
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 0)
  }

  func testAnotherDevicesTurnIsSteerableWhenItsPolicyIsNotBroader() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    try await world.addSecondDevice(profile: .runReadOnly)

    let outcome = await world.gateway.execute(
      command: try steerCommand(commandID: UUID()),
      context: NetworkCommandContext(
        deviceID: world.otherDeviceID, sessionID: world.otherSessionID),
      now: Self.now
    )

    guard case .completed = outcome else {
      return XCTFail("an equally scoped device may steer: \(outcome)")
    }
  }

  // MARK: - The runAgent gate still applies first

  func testSteeringWithoutRunAgentIsDeniedByCapability() async throws {
    let world = try await World(capabilities: [.view, .interrupt], profile: .runWorkspace)

    let outcome = await world.execute(try steerCommand())

    XCTAssertEqual(outcome, .denied(.capabilityMissing))
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 0)
  }

  func testSteeringWithARestrictiveProfileIsDeniedByTheCeiling() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .observe)

    let outcome = await world.execute(try steerCommand())

    XCTAssertEqual(outcome, .denied(.actionProfileTooRestrictive))
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 0)
  }

  func testARevokedDeviceCannotSteer() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    _ = try await world.authority.revoke(deviceID: deviceID)

    let outcome = await world.execute(try steerCommand())

    XCTAssertEqual(outcome, .denied(.revokedDevice))
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 0)
  }

  func testADegradedRuntimeMakesNoSteerCall() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    world.runtime.setReady(false)

    let outcome = await world.execute(try steerCommand())

    XCTAssertEqual(outcome, .denied(.runtimeUnavailable))
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 0)
  }

  // MARK: - Idempotency and crash boundaries

  func testDuplicateSteersProduceExactlyOneExternalCall() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    let command = try steerCommand()

    for _ in 0..<5 {
      _ = await world.execute(command)
    }

    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 1)
  }

  func testASteerAcrossAReconnectProducesOneCallAndReplays() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    _ = await world.execute(try steerCommand())

    let reconnected = UUID()
    world.sessions.register(deviceID: deviceID, sessionID: reconnected)
    let retry = try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now.addingTimeInterval(12),
      body: .steerTurn(threadID: "thread-a", turnID: "turn-1", prompt: "steer it")
    )
    let outcome = await world.gateway.execute(
      command: retry,
      context: NetworkCommandContext(deviceID: deviceID, sessionID: reconnected),
      now: Self.now.addingTimeInterval(12)
    )

    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 1)
    guard case .replayed = outcome else { return XCTFail("expected a replay") }
  }

  func testAFailedSteerIsAmbiguousAndNeverResent() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    await world.turnSteerer.setFailure(CodexRuntimeRequestError.notReady)
    let command = try steerCommand()

    let first = await world.execute(command)
    guard case .outcomeUnknown(let record) = first else {
      return XCTFail("a failed steer must be outcomeUnknown")
    }
    XCTAssertEqual(record.resultCode, .codexUnavailable)

    await world.turnSteerer.setFailure(nil)
    let second = await world.execute(command)

    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 1, "the steer must never be resent")
    guard case .outcomeUnknown = second else {
      return XCTFail("the ambiguous outcome must persist")
    }
  }

  func testACrashBetweenClaimAndSteerResolvesToOutcomeUnknown() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    let command = try steerCommand()
    _ = try await world.ledger.claim(
      deviceID: deviceID,
      commandID: command.commandID,
      kind: .steerTurn,
      semanticDigest: SemanticCommandDigest.digest(
        of: command, projectID: "project-a", effectiveProfile: .runReadOnly),
      at: Self.now
    )

    let outcome = await world.execute(command)

    guard case .outcomeUnknown(let record) = outcome else {
      return XCTFail("expected outcomeUnknown")
    }
    XCTAssertEqual(record.resultCode, .bridgeRestartedBeforeOutcome)
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 0)
  }

  func testADifferentSteerPromptUnderTheSameCommandIdentifierFailsClosed() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())
    _ = await world.execute(try steerCommand())

    let collided = try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now,
      body: .steerTurn(threadID: "thread-a", turnID: "turn-1", prompt: "something else")
    )
    let outcome = await world.execute(collided)

    XCTAssertEqual(outcome, .denied(.duplicateMismatch))
    let count = await world.turnSteerer.steerCount
    XCTAssertEqual(count, 1)
  }

  // MARK: - The seam cannot widen a turn

  func testTheSteeringSeamCarriesNoPolicyField() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-1")
    _ = await world.execute(try promptCommand())

    _ = await world.execute(try steerCommand())

    // What the seam received is exactly a target and text: there is no
    // sandbox, root, network, or approval value it could have carried.
    let steered = await world.turnSteerer.steered
    XCTAssertEqual(steered.count, 1)
    let recorded = await world.turnPolicies.policy(threadID: "thread-a", turnID: "turn-1")
    XCTAssertEqual(recorded?.policy.sandbox, .readOnly)
    XCTAssertEqual(recorded?.effectiveProfile, .runReadOnly)
  }

  func testTheCommandSchemaGivesSteeringNoPolicyField() throws {
    let encoded = try JSONEncoder().encode(try steerCommand())
    let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    let body = try XCTUnwrap(json["body"] as? [String: Any])

    XCTAssertEqual(Set(body.keys), ["type", "threadID", "turnID", "prompt"])
  }

  // MARK: - Fixtures

  private func recorded(
    turnID: String = "turn-1",
    profile: MobileActionProfile
  ) -> RecordedTurnPolicy {
    RecordedTurnPolicy(
      threadID: "thread-a",
      turnID: turnID,
      effectiveProfile: profile,
      policy: PhoneTurnPolicy.resolve(effectiveProfile: profile, writableRoots: []),
      startedByDeviceID: deviceID
    )
  }

  private func promptCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: UUID(),
      issuedAt: Self.now,
      body: .sendPrompt(threadID: "thread-a", prompt: "do the thing", attachmentIDs: [])
    )
  }

  private func steerCommand(commandID: UUID? = nil) throws -> ClientCommand {
    try ClientCommand(
      commandID: commandID ?? self.commandID,
      issuedAt: Self.now,
      body: .steerTurn(threadID: "thread-a", turnID: "turn-1", prompt: "steer it")
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
    let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
    let otherSessionID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
    private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

    init(
      projects: Set<String> = ["project-a"],
      capabilities: Set<DeviceCapability>,
      profile: MobileActionProfile,
      hostProfile: MobileActionProfile = .runWorkspace
    ) async throws {
      let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
      authority = DeviceGrantAuthority(
        storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
      _ = try await authority.addGrant(
        deviceID: deviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: capabilities,
        permittedProjectIDs: projects,
        actionProfileCeiling: profile
      )
      table.attribute(threadID: "thread-a", projectID: "project-a")
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
        readCursors: readCursors,
        hostProfile: hostProfile
      )
    }

    func execute(_ command: ClientCommand) async -> NetworkCommandOutcome {
      await gateway.execute(
        command: command, context: context, now: Date(timeIntervalSince1970: 1_000_000))
    }

    func addSecondDevice(profile: MobileActionProfile) async throws {
      _ = try await authority.addGrant(
        deviceID: otherDeviceID,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: [.view, .runAgent],
        permittedProjectIDs: ["project-a"],
        actionProfileCeiling: profile
      )
      sessions.register(deviceID: otherDeviceID, sessionID: otherSessionID)
    }
  }
}
