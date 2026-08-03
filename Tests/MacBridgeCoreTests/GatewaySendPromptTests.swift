import CodexAppServer
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Step 2.10 `sendPrompt`: gated a second time by the `runAgent` grant,
/// intersected down to the effective profile, and resolved entirely on the
/// Mac — the phone contributes a thread and a prompt and nothing else.
final class GatewaySendPromptTests: XCTestCase {
  private static let now = Date(timeIntervalSince1970: 1_000_000)
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let sessionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
  private let commandID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!

  // MARK: - The runAgent gate

  func testThePairingDefaultGrantCannotSendAPrompt() async throws {
    // Exactly what pairing creates: observe, empty scope, observe profile.
    let world = try await World(
      projects: [], capabilities: [.view], profile: .observe)

    let outcome = await world.execute(try promptCommand())

    XCTAssertEqual(outcome, .denied(.capabilityMissing))
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 0)
  }

  func testAGrantWithoutRunAgentIsDeniedEvenWithAnAgentProfile() async throws {
    let world = try await World(capabilities: [.view, .interrupt], profile: .runWorkspace)

    let outcome = await world.execute(try promptCommand())

    XCTAssertEqual(outcome, .denied(.capabilityMissing))
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 0)
  }

  func testRunAgentWithARestrictiveProfileIsDeniedByTheProfileCeiling() async throws {
    for profile in [MobileActionProfile.observe, .respond] {
      let world = try await World(
        capabilities: [.view, .runAgent], profile: profile)

      let outcome = await world.execute(try promptCommand())

      XCTAssertEqual(outcome, .denied(.actionProfileTooRestrictive), "\(profile)")
      let count = await world.turnStarter.startCount
      XCTAssertEqual(count, 0)
    }
  }

  func testTheHostProfileCapsTheDeviceProfile() async throws {
    // The grant permits workspace writes but the host does not.
    let world = try await World(
      capabilities: [.view, .runAgent], profile: .runWorkspace, hostProfile: .runReadOnly)
    world.workspaceRoots.setRoots(["/Users/example/project-a"], for: "project-a")

    let outcome = await world.execute(try promptCommand())

    guard case .completed = outcome else { return XCTFail("expected completion") }
    let started = await world.turnStarter.started
    XCTAssertEqual(started.first?.policy.sandbox, .readOnly)
    XCTAssertEqual(started.first?.policy.writableRoots, [])
  }

  // MARK: - Happy path

  func testAnAuthorizedPromptStartsExactlyOneTurn() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setNextTurnID("turn-99")

    let outcome = await world.execute(try promptCommand())

    guard case .completed(let record) = outcome else { return XCTFail("expected completion") }
    XCTAssertEqual(record.state, .succeeded)
    XCTAssertEqual(record.threadID, "thread-a")
    XCTAssertEqual(record.turnID, "turn-99")
    let started = await world.turnStarter.started
    XCTAssertEqual(started.count, 1)
    XCTAssertEqual(started.first?.threadID, "thread-a")
    XCTAssertEqual(started.first?.prompt, "do the thing")
  }

  func testDuplicatePromptsStartExactlyOneTurn() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    let command = try promptCommand()

    for _ in 0..<5 {
      _ = await world.execute(command)
    }

    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 1)
  }

  func testAPromptAcrossAReconnectStartsOneTurnAndReplaysTheResult() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    _ = await world.execute(try promptCommand())

    let reconnected = UUID()
    world.sessions.register(deviceID: deviceID, sessionID: reconnected)
    let retry = try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now.addingTimeInterval(15),
      body: .sendPrompt(threadID: "thread-a", prompt: "do the thing", attachmentIDs: [])
    )
    let outcome = await world.gateway.execute(
      command: retry,
      context: NetworkCommandContext(deviceID: deviceID, sessionID: reconnected),
      now: Self.now.addingTimeInterval(15)
    )

    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 1)
    guard case .replayed = outcome else { return XCTFail("expected a replay") }
  }

  // MARK: - Mac-resolved turn policy

  func testTheMacResolvesEveryTurnSettingAndTheProfileDecidesTheSandbox() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runWorkspace)
    world.workspaceRoots.setRoots(["/Users/example/project-a"], for: "project-a")

    _ = await world.execute(try promptCommand())

    let started = await world.turnStarter.started
    let policy = try XCTUnwrap(started.first?.policy)
    XCTAssertEqual(policy.sandbox, .workspaceWrite)
    XCTAssertEqual(policy.writableRoots, ["/Users/example/project-a"])
    XCTAssertFalse(policy.networkAccess)
    XCTAssertEqual(policy.approvalPolicy, .untrusted)
  }

  func testWorkspaceWithoutBridgeSuppliedRootsResolvesDownToReadOnly() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runWorkspace)

    _ = await world.execute(try promptCommand())

    let started = await world.turnStarter.started
    let policy = try XCTUnwrap(started.first?.policy)
    XCTAssertEqual(policy.sandbox, .readOnly)
    XCTAssertEqual(policy.writableRoots, [])
  }

  func testTheDefaultResolverGivesNoProjectWritableRoots() {
    XCTAssertEqual(
      DeniedWorkspaceRootResolver().writableRoots(forProjectID: "project-a"), [])
  }

  func testNetworkAccessAndApprovalPolicyCanNeverBeMadePermissive() {
    for profile in MobileActionProfile.allCases {
      for roots in [[], ["/Users/example/project-a"]] {
        let policy = PhoneTurnPolicy.resolve(effectiveProfile: profile, writableRoots: roots)
        XCTAssertFalse(policy.networkAccess, "\(profile)")
        XCTAssertNotEqual(policy.approvalPolicy.rawValue, "never")
      }
    }
    // The vocabulary itself has no way to disable approvals.
    XCTAssertFalse(PhoneTurnPolicy.Approval.allCases.map(\.rawValue).contains("never"))
  }

  func testTurnParametersCarryOnlyTheThreadAndPromptFromThePhone() {
    let policy = PhoneTurnPolicy.resolve(
      effectiveProfile: .runWorkspace, writableRoots: ["/Users/example/project-a"])

    let params = policy.turnStartParameters(threadID: "thread-a", prompt: "hello")

    let keys: Set<String> = Set(params.object?.keys ?? [:].keys)
    XCTAssertEqual(keys, ["threadId", "input", "approvalPolicy", "sandboxPolicy", "summary"])
    XCTAssertEqual(params["threadId"].string, "thread-a")
    XCTAssertEqual(params["input"].array?.first?["text"].string, "hello")
    XCTAssertEqual(params["sandboxPolicy"]["type"].string, "workspaceWrite")
    XCTAssertEqual(params["sandboxPolicy"]["networkAccess"].bool, false)
    XCTAssertEqual(
      params["sandboxPolicy"]["writableRoots"].array?.first?.string,
      "/Users/example/project-a"
    )
  }

  func testReadOnlyParametersCarryNoWritableRoots() {
    let policy = PhoneTurnPolicy.resolve(effectiveProfile: .runReadOnly, writableRoots: [])

    let params = policy.turnStartParameters(threadID: "thread-a", prompt: "hello")

    XCTAssertEqual(params["sandboxPolicy"]["type"].string, "readOnly")
    XCTAssertNil(params["sandboxPolicy"].object?["writableRoots"])
  }

  func testTheCommandSchemaGivesThePhoneNoPolicyFieldAtAll() throws {
    let encoded = try JSONEncoder().encode(try promptCommand())
    let json = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    let body = try XCTUnwrap(json["body"] as? [String: Any])

    XCTAssertEqual(Set(body.keys), ["type", "threadID", "prompt", "attachmentIDs"])
    for forbidden in ["sandboxPolicy", "approvalPolicy", "cwd", "writableRoots", "networkAccess"] {
      XCTAssertNil(body[forbidden], forbidden)
    }
  }

  // MARK: - Denials and failures

  func testNonemptyAttachmentsAreStillRejected() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runWorkspace)
    let command = try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now,
      body: .sendPrompt(
        threadID: "thread-a", prompt: "do the thing", attachmentIDs: ["attachment-1"])
    )

    let outcome = await world.execute(command)

    XCTAssertEqual(outcome, .denied(.attachmentsUnsupported))
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 0)
  }

  func testARevokedDeviceStartsNoTurn() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    _ = try await world.authority.revoke(deviceID: deviceID)

    let outcome = await world.execute(try promptCommand())

    XCTAssertEqual(outcome, .denied(.revokedDevice))
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 0)
  }

  func testACrossProjectThreadStartsNoTurn() async throws {
    let world = try await World(
      projects: ["project-a"], capabilities: [.view, .runAgent], profile: .runReadOnly)
    let command = try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now,
      body: .sendPrompt(threadID: "thread-b", prompt: "do the thing", attachmentIDs: [])
    )

    let outcome = await world.execute(command)

    XCTAssertEqual(outcome, .denied(.projectNotAllowed))
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 0)
  }

  func testADegradedRuntimeStartsNoTurn() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    world.runtime.setReady(false)

    let outcome = await world.execute(try promptCommand())

    XCTAssertEqual(outcome, .denied(.runtimeUnavailable))
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 0)
  }

  func testAFailedTurnStartIsAmbiguousAndNeverResent() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    await world.turnStarter.setFailure(CodexRuntimeRequestError.notReady)
    let command = try promptCommand()

    let first = await world.execute(command)
    guard case .outcomeUnknown(let record) = first else {
      return XCTFail("a failed turn start must be outcomeUnknown")
    }
    XCTAssertEqual(record.resultCode, .codexUnavailable)

    await world.turnStarter.setFailure(nil)
    let second = await world.execute(command)

    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 1, "the prompt must never be resent")
    guard case .outcomeUnknown = second else {
      return XCTFail("the ambiguous outcome must persist")
    }
  }

  func testACrashBetweenClaimAndTurnStartResolvesToOutcomeUnknown() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    let command = try promptCommand()
    _ = try await world.ledger.claim(
      deviceID: deviceID,
      commandID: command.commandID,
      kind: .sendPrompt,
      semanticDigest: SemanticCommandDigest.digest(
        of: command, projectID: "project-a", effectiveProfile: .runReadOnly),
      at: Self.now
    )

    let outcome = await world.execute(command)

    guard case .outcomeUnknown(let record) = outcome else {
      return XCTFail("expected outcomeUnknown")
    }
    XCTAssertEqual(record.resultCode, .bridgeRestartedBeforeOutcome)
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 0)
  }

  func testADifferentPromptUnderTheSameCommandIdentifierFailsClosed() async throws {
    let world = try await World(capabilities: [.view, .runAgent], profile: .runReadOnly)
    _ = await world.execute(try promptCommand())

    let collided = try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now,
      body: .sendPrompt(threadID: "thread-a", prompt: "do something else", attachmentIDs: [])
    )
    let outcome = await world.execute(collided)

    XCTAssertEqual(outcome, .denied(.duplicateMismatch))
    let count = await world.turnStarter.startCount
    XCTAssertEqual(count, 1)
  }

  /// The effective policy is part of command identity, so the same prompt
  /// under a different resolved profile is a different command.
  func testTheEffectivePolicyIsPartOfCommandIdentity() throws {
    let command = try promptCommand()

    let readOnly = SemanticCommandDigest.digest(
      of: command, projectID: "project-a", effectiveProfile: .runReadOnly)
    let workspace = SemanticCommandDigest.digest(
      of: command, projectID: "project-a", effectiveProfile: .runWorkspace)

    XCTAssertNotEqual(readOnly, workspace)
  }

  // MARK: - Fixtures

  private func promptCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: commandID,
      issuedAt: Self.now,
      body: .sendPrompt(threadID: "thread-a", prompt: "do the thing", attachmentIDs: [])
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
        readCursors: readCursors,
        hostProfile: hostProfile
      )
    }

    func execute(_ command: ClientCommand) async -> NetworkCommandOutcome {
      await gateway.execute(
        command: command, context: context, now: Date(timeIntervalSince1970: 1_000_000))
    }
  }
}
