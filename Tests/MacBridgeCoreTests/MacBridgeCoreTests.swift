import CompanionProtocol
import Foundation
import MacBridgeCore
import XCTest

final class MacBridgeCoreTests: XCTestCase {
  func testCommandRoundTripsWithStableSemanticType() throws {
    let command = try ClientCommand(
      commandID: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
      issuedAt: Date(timeIntervalSince1970: 1_754_000_000),
      body: .sendPrompt(
        threadID: "thread-1",
        prompt: "Continue the implementation",
        attachmentIDs: ["attachment-1"]
      )
    )
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .millisecondsSince1970
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(command)

    let json = String(decoding: data, as: UTF8.self)
    XCTAssertTrue(json.contains(#""type":"sendPrompt""#))
    XCTAssertFalse(json.contains("sandbox"))
    XCTAssertFalse(json.contains("approvalPolicy"))

    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .millisecondsSince1970
    XCTAssertEqual(try decoder.decode(ClientCommand.self, from: data), command)
  }

  func testUnknownCommandTypeFailsClosed() throws {
    let data = Data(
      #"{"commandID":"11111111-1111-1111-1111-111111111111","issuedAt":0,"body":{"type":"deleteThread"}}"#
        .utf8
    )

    XCTAssertThrowsError(try JSONDecoder().decode(ClientCommand.self, from: data))
  }

  func testUnknownCommandFieldFailsClosed() throws {
    let data = Data(
      #"{"commandID":"11111111-1111-1111-1111-111111111111","issuedAt":0,"body":{"type":"interruptTurn","threadID":"thread-1","turnID":"turn-1","sandbox":"danger-full-access"}}"#
        .utf8
    )

    XCTAssertThrowsError(try JSONDecoder().decode(ClientCommand.self, from: data))
  }

  func testUnknownOuterCommandFieldFailsClosed() throws {
    let data = Data(
      #"{"commandID":"11111111-1111-1111-1111-111111111111","issuedAt":0,"body":{"type":"interruptTurn","threadID":"thread-1","turnID":"turn-1"},"admin":true}"#
        .utf8
    )

    XCTAssertThrowsError(try JSONDecoder().decode(ClientCommand.self, from: data))
  }

  func testInvalidPromptIsRejectedBeforeEncoding() throws {
    XCTAssertThrowsError(
      try ClientCommand(
        commandID: UUID(),
        issuedAt: Date(),
        body: .sendPrompt(threadID: "thread-1", prompt: "   ", attachmentIDs: [])
      )
    ) { error in
      XCTAssertEqual(error as? CompanionCommandValidationError, .invalidPrompt)
    }
  }

  func testWhitespaceOpaqueIDIsRejected() throws {
    XCTAssertThrowsError(
      try ClientCommand(
        commandID: UUID(),
        issuedAt: Date(),
        body: .selectThread(threadID: " thread-1")
      )
    ) { error in
      XCTAssertEqual(
        error as? CompanionCommandValidationError,
        .invalidOpaqueID(field: "threadId")
      )
    }
  }

  func testProtocolCompatibilityRequiresMatchingMajorVersion() {
    XCTAssertTrue(ProtocolVersion.current.isCompatible(with: .init(major: 1, minor: 9)))
    XCTAssertFalse(ProtocolVersion.current.isCompatible(with: .init(major: 2, minor: 0)))
  }

  func testCapabilityPolicyAllowsOnlyWithinGrantAndEffectiveProfile() throws {
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .startThread(projectID: "project-1", prompt: "Inspect only", attachmentIDs: [])
    )
    let grant = DeviceGrant(
      deviceID: UUID(),
      capabilities: [.view, .runAgent, .startThread],
      permittedProjectIDs: ["project-1"],
      actionProfile: .runWorkspace
    )

    XCTAssertEqual(
      CapabilityPolicy.authorize(
        command: command,
        grant: grant,
        resolvedProjectID: nil,
        hostProfile: .runReadOnly
      ),
      .allowed(effectiveProfile: .runReadOnly)
    )
  }

  func testCapabilityPolicyDeniesCrossProjectAndRevokedDevices() throws {
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .interruptTurn(threadID: "thread-1", turnID: "turn-1")
    )
    let grant = DeviceGrant(
      deviceID: UUID(),
      capabilities: [.interrupt],
      permittedProjectIDs: ["project-1"],
      actionProfile: .observe
    )
    XCTAssertEqual(
      CapabilityPolicy.authorize(
        command: command,
        grant: grant,
        resolvedProjectID: "project-2",
        hostProfile: .runReadOnly
      ),
      .denied(.projectNotAllowed)
    )

    let revoked = DeviceGrant(
      deviceID: grant.deviceID,
      capabilities: grant.capabilities,
      permittedProjectIDs: grant.permittedProjectIDs,
      actionProfile: grant.actionProfile,
      isRevoked: true
    )
    XCTAssertEqual(
      CapabilityPolicy.authorize(
        command: command,
        grant: revoked,
        resolvedProjectID: "project-1",
        hostProfile: .runReadOnly
      ),
      .denied(.revokedDevice)
    )
  }

  func testCapabilityPolicyDeniesNaturalLanguageWorkForObserveProfile() throws {
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(),
      body: .sendPrompt(threadID: "thread-1", prompt: "Run tests", attachmentIDs: [])
    )
    let grant = DeviceGrant(
      deviceID: UUID(),
      capabilities: [.runAgent],
      permittedProjectIDs: ["project-1"],
      actionProfile: .observe
    )

    XCTAssertEqual(
      CapabilityPolicy.authorize(
        command: command,
        grant: grant,
        resolvedProjectID: "project-1",
        hostProfile: .runWorkspace
      ),
      .denied(.actionProfileTooRestrictive)
    )
  }

  func testCapabilityPolicyRejectsStaleCommand() throws {
    let now = Date(timeIntervalSince1970: 1_000)
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: now.addingTimeInterval(-61),
      body: .selectThread(threadID: "thread-1")
    )
    let grant = DeviceGrant(
      deviceID: UUID(),
      capabilities: [.view],
      permittedProjectIDs: ["project-1"],
      actionProfile: .observe
    )

    XCTAssertEqual(
      CapabilityPolicy.authorize(
        command: command,
        grant: grant,
        resolvedProjectID: "project-1",
        hostProfile: .observe,
        now: now
      ),
      .denied(.staleCommand)
    )
  }

  func testEventJournalReplaysOrRequiresSnapshotWhenCursorIsTooOld() async throws {
    let journal = try EventJournal<String>(capacity: 2)
    _ = try await journal.append("one")
    let two = try await journal.append("two")
    let three = try await journal.append("three")

    let staleReplay = try await journal.replay(after: 0)
    let currentReplay = try await journal.replay(after: 1)

    XCTAssertEqual(staleReplay, .snapshotRequired(latestSequence: 3))
    XCTAssertEqual(currentReplay, .events([two, three]))
  }

  func testEventJournalRejectsCursorAheadOfHost() async throws {
    let journal = try EventJournal<String>(capacity: 2)
    _ = try await journal.append("one")

    do {
      _ = try await journal.replay(after: 2)
      XCTFail("Expected an ahead cursor to fail closed.")
    } catch let error as EventJournalError {
      XCTAssertEqual(error, .cursorAhead(latestSequence: 1))
    }
  }

  func testCommandLedgerReplaysKnownCommandAndRejectsChangedBody() async throws {
    let ledger = InMemoryCommandLedger()
    let commandID = UUID()
    let deviceID = UUID()
    let first = try ClientCommand(
      commandID: commandID,
      issuedAt: Date(timeIntervalSince1970: 100),
      body: .interruptTurn(threadID: "thread-1", turnID: "turn-1")
    )
    let changed = try ClientCommand(
      commandID: commandID,
      issuedAt: first.issuedAt,
      body: .interruptTurn(threadID: "thread-1", turnID: "turn-2")
    )

    guard
      case .accepted(let accepted) = try await ledger.register(
        deviceID: deviceID,
        command: first
      )
    else {
      return XCTFail("Expected a new command to be accepted.")
    }
    guard
      case .replay(let replayed) = try await ledger.register(
        deviceID: deviceID,
        command: first
      )
    else {
      return XCTFail("Expected an identical command to replay its record.")
    }
    XCTAssertEqual(replayed, accepted)

    do {
      _ = try await ledger.register(deviceID: deviceID, command: changed)
      XCTFail("Expected a changed body with the same ID to be rejected.")
    } catch let error as CommandLedgerError {
      XCTAssertEqual(error, .commandIDCollision)
    }
  }

  func testCommandLedgerMarksCrashAmbiguousWorkUnknownAndNeverReregisters() async throws {
    let ledger = InMemoryCommandLedger()
    let command = try ClientCommand(
      commandID: UUID(),
      issuedAt: Date(timeIntervalSince1970: 100),
      body: .sendPrompt(threadID: "thread-1", prompt: "Continue", attachmentIDs: [])
    )
    let deviceID = UUID()
    _ = try await ledger.register(deviceID: deviceID, command: command)
    try await ledger.markSubmitted(commandID: command.commandID, threadID: "thread-1")
    await ledger.markInFlightOutcomesUnknown()

    guard
      case .replay(let record) = try await ledger.register(
        deviceID: deviceID,
        command: command
      )
    else {
      return XCTFail("An ambiguous command must replay instead of executing again.")
    }
    XCTAssertEqual(record.state, .outcomeUnknown)
    XCTAssertEqual(record.resultCode, .bridgeRestartedBeforeOutcome)
  }

  func testAgentSlotStatusUsesAttentionFirstPrecedence() {
    XCTAssertEqual(
      AgentSlotStatus.derive(
        isAssigned: true,
        hasPendingInput: true,
        hasActiveTurn: true,
        hasUnreadFailure: true,
        hasUnreadCompletion: true
      ),
      .inputRequired
    )
    XCTAssertEqual(
      AgentSlotStatus.derive(
        isAssigned: false,
        hasPendingInput: true,
        hasActiveTurn: true,
        hasUnreadFailure: true,
        hasUnreadCompletion: true
      ),
      .unassigned
    )
  }

}
