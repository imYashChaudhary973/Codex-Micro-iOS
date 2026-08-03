import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import NIOCore
import NIOEmbedded
import XCTest

@testable import MacBridgeServer

/// Deterministic gateway seam that records exactly what the transport handed
/// it and returns a scripted outcome.
actor FakeListenerCommandHandler: ListenerCommandHandling {
  private(set) var received: [(command: ClientCommand, deviceID: UUID, sessionID: UUID)] = []
  private var outcome: ListenerCommandOutcome = .completed

  func setOutcome(_ value: ListenerCommandOutcome) { outcome = value }

  var callCount: Int { received.count }

  func execute(
    command: ClientCommand,
    deviceID: UUID,
    sessionID: UUID
  ) async -> ListenerCommandOutcome {
    received.append((command, deviceID, sessionID))
    return outcome
  }
}

/// Step 2.9 sealed command carriage: the transport decodes strictly, hands
/// the command to the gateway seam with the authenticated identity, and
/// carries the closed result back sealed.
final class ListenerCommandTransportTests: XCTestCase {
  private let connectionID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let sessionID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
  private let commandID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!

  // MARK: - Seam contract

  func testTheTransportCarriesOneOpaqueCommandEnvelopeNotPerCommandKinds() {
    let raw = Set(ListenerApplicationKind.allCases.map(\.rawValue))

    XCTAssertTrue(raw.contains("commandRequest"))
    XCTAssertTrue(raw.contains("commandResult"))
    for perCommand in [
      "interruptTurn", "markThreadRead", "sendPrompt", "steerTurn", "startThread",
      "resolveApproval", "selectThread",
    ] {
      XCTAssertFalse(raw.contains(perCommand), perCommand)
    }
  }

  func testTheDenyingDefaultExecutesNothing() async {
    let outcome = await DenyingListenerCommandHandler().execute(
      command: try! interruptCommand(), deviceID: deviceID, sessionID: sessionID)

    XCTAssertEqual(outcome, .denied(.unsupportedCommand))
  }

  func testEveryOutcomeMapsOntoTheClosedWireVocabulary() throws {
    let cases: [(ListenerCommandOutcome, SecureCommandOutcome)] = [
      (.completed, .completed),
      (.failed, .failed),
      (.outcomeUnknown, .outcomeUnknown),
      (.denied(.capabilityMissing), .denied),
    ]

    for (outcome, expected) in cases {
      let result = try outcome.wireResult(commandID: commandID)
      XCTAssertEqual(result.outcome, expected)
      XCTAssertEqual(result.commandID, commandID)
      XCTAssertEqual(result.denialReason != nil, expected == .denied)
    }
  }

  func testEveryDenialReasonIsRepresentableOnTheWire() throws {
    for reason in SecureCommandDenialReason.allCases {
      let result = try ListenerCommandOutcome.denied(reason).wireResult(commandID: commandID)
      XCTAssertEqual(result.denialReason, reason)
    }
  }

  // MARK: - Sealed round trip

  func testACommandReachesTheGatewayWithTheAuthenticatedIdentity() async throws {
    let world = try await World(deviceID: deviceID, sessionID: sessionID)

    try await world.authenticate()
    try await world.sendCommand(try interruptCommand())
    await world.settle()

    let received = await world.commands.received
    XCTAssertEqual(received.count, 1)
    XCTAssertEqual(received.first?.deviceID, deviceID)
    XCTAssertEqual(received.first?.sessionID, sessionID)
    XCTAssertEqual(received.first?.command.commandID, commandID)
  }

  func testTheClosedResultIsSealedAndReturned() async throws {
    let world = try await World(deviceID: deviceID, sessionID: sessionID)
    await world.commands.setOutcome(.denied(.capabilityMissing))

    try await world.authenticate()
    try await world.sendCommand(try interruptCommand())
    await world.settle()

    let result = try await world.readCommandResult()
    XCTAssertEqual(result.commandID, commandID)
    XCTAssertEqual(result.outcome, .denied)
    XCTAssertEqual(result.denialReason, .capabilityMissing)
  }

  func testAnOutcomeUnknownResultCarriesNoDenialReason() async throws {
    let world = try await World(deviceID: deviceID, sessionID: sessionID)
    await world.commands.setOutcome(.outcomeUnknown)

    try await world.authenticate()
    try await world.sendCommand(try interruptCommand())
    await world.settle()

    let result = try await world.readCommandResult()
    XCTAssertEqual(result.outcome, .outcomeUnknown)
    XCTAssertNil(result.denialReason)
  }

  // MARK: - Strictness

  func testAMalformedCommandBodyClosesWithoutReachingTheGateway() async throws {
    let world = try await World(deviceID: deviceID, sessionID: sessionID)

    try await world.authenticate()
    try await world.send(kind: .commandRequest, body: Data(#"{"commandID":"not-a-uuid"}"#.utf8))
    await world.settle()

    let reason = try await world.readCloseReason()
    XCTAssertEqual(reason, .protocolViolation)
    let count = await world.commands.callCount
    XCTAssertEqual(count, 0)
  }

  func testACommandWithUnknownFieldsIsRejected() async throws {
    let world = try await World(deviceID: deviceID, sessionID: sessionID)
    let body = Data(
      #"{"commandID":"66666666-6666-6666-6666-666666666666","issuedAt":1,"body":{"type":"interruptTurn","threadID":"t","turnID":"u"},"extra":1}"#
        .utf8)

    try await world.authenticate()
    try await world.send(kind: .commandRequest, body: body)
    await world.settle()

    let reason = try await world.readCloseReason()
    XCTAssertEqual(reason, .protocolViolation)
    let count = await world.commands.callCount
    XCTAssertEqual(count, 0)
  }

  func testAHostOriginatedResultArrivingInboundIsRejected() async throws {
    let world = try await World(deviceID: deviceID, sessionID: sessionID)

    try await world.authenticate()
    try await world.send(kind: .commandResult, body: Data(#"{}"#.utf8))
    await world.settle()

    let reason = try await world.readCloseReason()
    XCTAssertEqual(reason, .protocolViolation)
    let count = await world.commands.callCount
    XCTAssertEqual(count, 0)
  }

  func testACommandBeforeAuthenticationNeverReachesTheGateway() async throws {
    let world = try await World(deviceID: deviceID, sessionID: sessionID)

    await world.writeInbound(Data(repeating: 0x02, count: 48))
    await world.settle()

    let count = await world.commands.callCount
    XCTAssertEqual(count, 0)
    let outbound = try await world.readOutboundBytes()
    XCTAssertNil(outbound)
  }

  // MARK: - Fixtures

  private func interruptCommand() throws -> ClientCommand {
    try ClientCommand(
      commandID: commandID,
      issuedAt: Date(timeIntervalSince1970: 1_000_000),
      body: .interruptTurn(threadID: "thread-a", turnID: "turn-1")
    )
  }

  /// One embedded authenticated connection with device-side codecs.
  private final class World {
    let channel: NIOAsyncTestingChannel
    let commands = FakeListenerCommandHandler()
    let registry = ListenerSessionFrameRegistry()
    private var device: ListenerSessionFrames
    private let hostFrames: ListenerSessionFrames
    private let connectionID: UUID

    init(deviceID: UUID, sessionID: UUID) async throws {
      connectionID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
      let clientKey = SymmetricKey(data: Data(repeating: 0xC1, count: 32))
      let serverKey = SymmetricKey(data: Data(repeating: 0x5E, count: 32))
      hostFrames = ListenerSessionFrames(
        deviceID: deviceID,
        sessionID: sessionID,
        inbound: try SecureFrameOpener(
          key: clientKey, connectionID: sessionID, direction: .clientToServer),
        outbound: try SecureFrameSealer(
          key: serverKey, connectionID: sessionID, direction: .serverToClient)
      )
      device = ListenerSessionFrames(
        deviceID: deviceID,
        sessionID: sessionID,
        inbound: try SecureFrameOpener(
          key: serverKey, connectionID: sessionID, direction: .serverToClient),
        outbound: try SecureFrameSealer(
          key: clientKey, connectionID: sessionID, direction: .clientToServer)
      )
      channel = NIOAsyncTestingChannel()
      try await channel.pipeline.addHandler(
        ListenerObservationHandler(
          connectionID: connectionID,
          observation: DenyingListenerObservationHandler(),
          commands: commands,
          frameProvider: registry,
          logger: DiscardingListenerLogger()
        )
      )
      try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0))
    }

    func authenticate() async throws {
      await registry.store(hostFrames, connectionID: connectionID)
      let pipeline = channel.pipeline
      try await channel.testingEventLoop.executeInContext {
        pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())
      }
      await settle()
    }

    /// Drains the testing loop and any awaiting Tasks.
    ///
    /// The handler hands work to a `Task` and hops back through
    /// `eventLoop.execute`, so both have to be driven. `NIOAsyncTestingChannel`
    /// is used rather than `EmbeddedChannel` precisely because its loop is
    /// safe to drive from whichever thread resumes after an `await`.
    /// Drains the testing loop and the detached work the handler spawns.
    ///
    /// The handler hands work to a detached `Task` and hops back through
    /// `eventLoop.execute`. `Task.yield()` alone does **not** guarantee that
    /// detached task is scheduled, so a fixed spin of yields passes on an idle
    /// machine and fails under full-suite load — which is exactly how this
    /// helper first went flaky. Each round therefore runs the loop and then
    /// sleeps briefly, which does give the detached task a chance to run.
    func settle() async {
      for _ in 0..<64 {
        await channel.testingEventLoop.run()
        await Task.yield()
        try? await Task.sleep(nanoseconds: 100_000)
      }
      await channel.testingEventLoop.run()
    }

    func writeInbound(_ bytes: Data) async {
      var buffer = channel.allocator.buffer(capacity: bytes.count)
      buffer.writeBytes(bytes)
      _ = try? await channel.writeInbound(buffer)
    }

    func sendCommand(_ command: ClientCommand) async throws {
      let encoder = JSONEncoder()
      encoder.outputFormatting = [.sortedKeys]
      try await send(kind: .commandRequest, body: try encoder.encode(command))
    }

    func send(kind: ListenerApplicationKind, body: Data) async throws {
      let envelope = try ListenerApplicationEnvelope(kind: kind, payload: body)
      await writeInbound(try device.outbound.seal(try envelope.encoded()))
    }

    func readOutboundBytes() async throws -> Data? {
      guard var buffer = try await channel.readOutbound(as: ByteBuffer.self) else { return nil }
      return buffer.readData(length: buffer.readableBytes)
    }

    func readEnvelope() async throws -> ListenerApplicationEnvelope? {
      guard let bytes = try await readOutboundBytes() else { return nil }
      return try ListenerApplicationEnvelope.decode(try device.inbound.open(bytes))
    }

    func readCommandResult() async throws -> SecureCommandResult {
      let decoded = try await readEnvelope()
      let envelope = try XCTUnwrap(decoded)
      XCTAssertEqual(envelope.kind, .commandResult)
      return try JSONDecoder().decode(SecureCommandResult.self, from: envelope.payload)
    }

    func readCloseReason() async throws -> SecureCloseReason? {
      guard let envelope = try await readEnvelope(), envelope.kind == .closeNotice else {
        return nil
      }
      return try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload).reason
    }
  }
}
