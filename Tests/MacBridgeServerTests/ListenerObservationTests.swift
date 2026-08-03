import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import NIOCore
import NIOEmbedded
import XCTest

@testable import MacBridgeServer

/// Step 2.8 sealed post-authentication observation carriage: the closed
/// application allowlist, one-shot frame ownership, exactly-next sealed
/// frames, and the closed post-authentication reasons.
final class ListenerObservationTests: XCTestCase {
  private let connectionID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let subscriptionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!

  // MARK: - Allowlist

  func testExactlyThreeKindsAreDeviceOriginated() {
    let inbound = ListenerApplicationKind.allCases.filter(\.isDeviceOriginated)

    XCTAssertEqual(
      Set(inbound), [.observationSubscribe, .observationAcknowledge, .commandRequest])
    XCTAssertEqual(ListenerApplicationKind.allCases.count, 6)
  }

  func testTheApplicationVocabularyHasNoCommandOrApprovalKind() {
    let raw = Set(ListenerApplicationKind.allCases.map(\.rawValue))

    // The transport carries one opaque command envelope, never a per-command
    // kind, so no wire change here can enable a command the gateway has not
    // accepted.
    for forbidden in [
      "sendPrompt", "steerTurn", "interruptTurn", "markThreadRead", "startThread",
      "resolveApproval", "selectThread",
    ] {
      XCTAssertFalse(raw.contains(forbidden), forbidden)
    }
  }

  func testEnvelopeRejectsUnknownFieldsEmptyAndOversizedBodies() {
    XCTAssertThrowsError(
      try ListenerApplicationEnvelope.decode(
        Data(#"{"kind":"observationSubscribe","payload":"","extra":1}"#.utf8)))
    XCTAssertThrowsError(
      try ListenerApplicationEnvelope(kind: .observationSubscribe, payload: Data()))
    XCTAssertThrowsError(
      try ListenerApplicationEnvelope(
        kind: .observationSubscribe,
        payload: Data(repeating: 0x01, count: ListenerApplicationEnvelope.maxPayloadBytes + 1)))
    XCTAssertThrowsError(
      try ListenerApplicationEnvelope.decode(
        Data(#"{"kind":"interruptTurn","payload":"AQ=="}"#.utf8)))
  }

  func testRefusalsMapOntoTheClosedWireVocabulary() {
    XCTAssertEqual(ListenerObservationRefusal.notAuthorized.closeReason, .deviceRevoked)
    XCTAssertEqual(
      ListenerObservationRefusal.authorityUnavailable.closeReason, .authorizationChanged)
    XCTAssertEqual(ListenerObservationRefusal.cursorRejected.closeReason, .counterViolation)
    XCTAssertEqual(ListenerObservationRefusal.protocolViolation.closeReason, .protocolViolation)
  }

  func testDenyingDefaultsDiscloseNothing() async {
    let denying = DenyingListenerObservationHandler()
    let provider = DenyingListenerSessionFrameProvider()

    await assertThrowsErrorAsync(
      try await denying.subscribe(
        deviceID: deviceID, subscriptionID: subscriptionID, resumeCursor: nil)
    ) { error in
      XCTAssertEqual(error as? ListenerObservationRefusal, .notAuthorized)
    }
    let frames = await provider.takeFrames(connectionID: connectionID)
    XCTAssertNil(frames)
  }

  // MARK: - Frame ownership

  func testFrameOwnershipTransfersExactlyOnce() async throws {
    let registry = ListenerSessionFrameRegistry()
    await registry.store(try makeFrames().host, connectionID: connectionID)

    let first = await registry.takeFrames(connectionID: connectionID)
    let second = await registry.takeFrames(connectionID: connectionID)

    XCTAssertNotNil(first)
    XCTAssertNil(second)
    let pending = await registry.pendingCount
    XCTAssertEqual(pending, 0)
  }

  func testDiscardingFramesLeavesNothingToClaim() async throws {
    let registry = ListenerSessionFrameRegistry()
    await registry.store(try makeFrames().host, connectionID: connectionID)

    await registry.discardFrames(connectionID: connectionID)

    let claimed = await registry.takeFrames(connectionID: connectionID)
    XCTAssertNil(claimed)
  }

  func testSessionFramesAreRedacted() throws {
    let frames = try makeFrames().host

    XCTAssertEqual("\(frames)", "ListenerSessionFrames(redacted)")
    XCTAssertTrue(Mirror(reflecting: frames).children.isEmpty)
    var dumped = ""
    dump(frames, to: &dumped)
    XCTAssertFalse(dumped.contains("outbound"))
  }

  // MARK: - Sealed round trip through the handler

  func testSubscribeReturnsASealedFilteredSnapshot() async throws {
    let world = try await World(deviceID: deviceID, connectionID: connectionID)
    let batch = ListenerObservationBatch(
      payload: .snapshot(try snapshotPayload()), cursor: try cursor(sequence: 0))
    await world.observation.setSubscribeResult(.success(batch))

    try await world.authenticate()
    try await world.sendSubscribe()
    await world.settle()

    let delivery = try await world.readDelivery()
    XCTAssertEqual(delivery.kind, .snapshot)
    XCTAssertEqual(delivery.subscriptionID, subscriptionID)
    XCTAssertEqual(delivery.cursor.sequence, 0)
    let decoded = try JSONDecoder().decode(
      SecureObservationSnapshot.self, from: delivery.payload)
    XCTAssertEqual(decoded.threads.map(\.threadID), ["thread-a"])
  }

  func testAcknowledgementDrainsTheNextBatch() async throws {
    let world = try await World(deviceID: deviceID, connectionID: connectionID)
    await world.observation.setSubscribeResult(
      .success(
        ListenerObservationBatch(
          payload: .snapshot(try snapshotPayload()), cursor: try cursor(sequence: 0))))
    await world.observation.setNextBatch(
      ListenerObservationBatch(
        payload: .events(try eventsPayload()), cursor: try cursor(sequence: 2)))

    try await world.authenticate()
    try await world.sendSubscribe()
    await world.settle()
    _ = try await world.readDelivery()
    try await world.sendAcknowledge(cursor: try cursor(sequence: 0))
    await world.settle()

    let delivery = try await world.readDelivery()
    XCTAssertEqual(delivery.kind, .event)
    XCTAssertEqual(delivery.cursor.sequence, 2)
    let acknowledged = await world.observation.acknowledgements
    XCTAssertEqual(acknowledged, 1)
  }

  func testCaughtUpAcknowledgementSendsNothing() async throws {
    let world = try await World(deviceID: deviceID, connectionID: connectionID)
    await world.observation.setSubscribeResult(
      .success(
        ListenerObservationBatch(
          payload: .snapshot(try snapshotPayload()), cursor: try cursor(sequence: 0))))

    try await world.authenticate()
    try await world.sendSubscribe()
    await world.settle()
    _ = try await world.readDelivery()
    try await world.sendAcknowledge(cursor: try cursor(sequence: 0))
    await world.settle()

    let outbound = try await world.readOutboundBytes()
    XCTAssertNil(outbound)
  }

  // MARK: - Closed failures

  func testAHostOriginatedKindArrivingInboundClosesTheConnection() async throws {
    let world = try await World(deviceID: deviceID, connectionID: connectionID)

    try await world.authenticate()
    try await world.send(kind: .observationDelivery, body: Data(#"{}"#.utf8))
    await world.settle()

    let reason = try await world.readCloseReason()
    XCTAssertEqual(reason, .protocolViolation)
  }

  func testATamperedSealedFrameClosesTheConnection() async throws {
    let world = try await World(deviceID: deviceID, connectionID: connectionID)

    try await world.authenticate()
    try await world.sendRawSealed { sealed in
      var tampered = sealed
      tampered[tampered.count - 1] ^= 0xFF
      return tampered
    }
    await world.settle()

    let reason = try await world.readCloseReason()
    XCTAssertEqual(reason, .counterViolation)
  }

  func testAReplayedSealedFrameClosesTheConnection() async throws {
    let world = try await World(deviceID: deviceID, connectionID: connectionID)
    await world.observation.setSubscribeResult(
      .success(
        ListenerObservationBatch(
          payload: .snapshot(try snapshotPayload()), cursor: try cursor(sequence: 0))))

    try await world.authenticate()
    let first = try world.sealSubscribe()
    await world.writeInbound(first)
    await world.settle()
    _ = try await world.readDelivery()
    await world.writeInbound(first)
    await world.settle()

    let reason = try await world.readCloseReason()
    XCTAssertEqual(reason, .counterViolation)
  }

  func testASeamRefusalClosesWithItsOwnPostAuthenticationReason() async throws {
    let cases: [(ListenerObservationRefusal, SecureCloseReason)] = [
      (.notAuthorized, .deviceRevoked),
      (.authorityUnavailable, .authorizationChanged),
      (.cursorRejected, .counterViolation),
    ]
    for (refusal, expected) in cases {
      let world = try await World(deviceID: deviceID, connectionID: connectionID)
      await world.observation.setSubscribeResult(.failure(refusal))

      try await world.authenticate()
      try await world.sendSubscribe()
      await world.settle()

      let reason = try await world.readCloseReason()
      XCTAssertEqual(reason, expected, "\(refusal)")
    }
  }

  /// A build with no wired frame provider keeps the Step 2.7 behaviour: an
  /// authenticated connection is admitted and kept alive, and nothing is
  /// delivered to it. It must not be killed just because this step exists.
  func testAnAuthenticatedConnectionWithNoSessionCodecsStaysAliveAndInert() async throws {
    let world = try await World(
      deviceID: deviceID, connectionID: connectionID, storeFrames: false)

    try await world.authenticate()
    await world.settle()

    let outbound = try await world.readOutboundBytes()
    XCTAssertNil(outbound)
    XCTAssertTrue(world.channel.isActive)
  }

  /// It is inert, not permissive: a connection that can open nothing closes
  /// on the first application message, and closes silently because no sealed
  /// reason can be produced without codecs.
  func testAnInertConnectionClosesOnItsFirstApplicationMessage() async throws {
    let world = try await World(
      deviceID: deviceID, connectionID: connectionID, storeFrames: false)

    try await world.authenticate()
    await world.settle()
    await world.writeInbound(Data(repeating: 0x01, count: 64))
    await world.settle()

    let outbound = try await world.readOutboundBytes()
    XCTAssertNil(outbound)
    XCTAssertFalse(world.channel.isActive)
  }

  func testNothingIsWrittenBeforeAuthentication() async throws {
    let world = try await World(deviceID: deviceID, connectionID: connectionID)

    await world.writeInbound(Data(repeating: 0x01, count: 32))
    await world.settle()

    let outbound = try await world.readOutboundBytes()
    XCTAssertNil(outbound)
  }

  // MARK: - Fixtures

  private func snapshotPayload() throws -> SecureObservationSnapshot {
    try SecureObservationSnapshot(
      generatedAtEpochSeconds: 1_000,
      threads: [
        try ObservedThreadState(
          threadID: "thread-a", projectID: "project-a", status: .active,
          activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil)
      ]
    )
  }

  private func eventsPayload() throws -> SecureObservationEventBatch {
    try SecureObservationEventBatch(events: [
      try SecureObservationEvent(
        sequence: 1, kind: .threadUpdated, threadID: "thread-a", projectID: "project-a"),
      try SecureObservationEvent(
        sequence: 2, kind: .threadUpdated, threadID: "thread-a", projectID: "project-a"),
    ])
  }

  private func cursor(sequence: UInt64) throws -> ReplayCursorEnvelope {
    ReplayCursorEnvelope(
      deviceID: deviceID,
      grantRevision: 1,
      authorizedViewEpoch: 1,
      journalEpoch: try JournalEpoch(rawBytes: Data(repeating: 0x11, count: 16)),
      sequence: sequence
    )
  }

  private func makeFrames() throws -> (host: ListenerSessionFrames, device: ListenerSessionFrames) {
    let sessionID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
    let clientKey = SymmetricKey(data: Data(repeating: 0xC1, count: 32))
    let serverKey = SymmetricKey(data: Data(repeating: 0x5E, count: 32))
    let host = ListenerSessionFrames(
      deviceID: deviceID,
      sessionID: sessionID,
      inbound: try SecureFrameOpener(
        key: clientKey, connectionID: sessionID, direction: .clientToServer),
      outbound: try SecureFrameSealer(
        key: serverKey, connectionID: sessionID, direction: .serverToClient)
    )
    let device = ListenerSessionFrames(
      deviceID: deviceID,
      sessionID: sessionID,
      inbound: try SecureFrameOpener(
        key: serverKey, connectionID: sessionID, direction: .serverToClient),
      outbound: try SecureFrameSealer(
        key: clientKey, connectionID: sessionID, direction: .clientToServer)
    )
    return (host, device)
  }

  /// One embedded authenticated connection plus the device-side codecs, so a
  /// test can seal exactly what a real device would.
  private final class World {
    let channel: NIOAsyncTestingChannel
    let observation = FakeListenerObservationHandler()
    let registry = ListenerSessionFrameRegistry()
    private var device: ListenerSessionFrames
    private let subscriptionID: UUID
    private let deviceID: UUID
    private let connectionID: UUID
    private let storeFrames: Bool
    private let hostFrames: ListenerSessionFrames

    init(deviceID: UUID, connectionID: UUID, storeFrames: Bool = true) async throws {
      self.deviceID = deviceID
      self.connectionID = connectionID
      self.storeFrames = storeFrames
      self.subscriptionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
      let sessionID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
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
          observation: observation,
          frameProvider: registry,
          logger: DiscardingListenerLogger()
        )
      )
      try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0))
    }

    func authenticate() async throws {
      if storeFrames {
        await registry.store(hostFrames, connectionID: connectionID)
      }
      let pipeline = channel.pipeline
      try await channel.testingEventLoop.executeInContext {
        pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())
      }
      await settle()
    }

    /// Drains the event loop and any awaiting Tasks.
    ///
    /// The handler hands work to a `Task` and hops back through
    /// `eventLoop.execute`, so a fixed number of yields is not by itself a
    /// guarantee. The loop therefore keeps spinning until the channel has
    /// produced output or gone inactive, and only then stops.
    /// Drains the testing loop and any awaiting Tasks.
    ///
    /// The handler hands work to a `Task` and hops back through
    /// `eventLoop.execute`, so both have to be driven. `NIOAsyncTestingChannel`
    /// is used rather than `EmbeddedChannel` precisely because its loop is
    /// safe to drive from whichever thread resumes after an `await`.
    func settle() async {
      for _ in 0..<64 {
        await Task.yield()
        await channel.testingEventLoop.run()
      }
    }

    func writeInbound(_ bytes: Data) async {
      var buffer = channel.allocator.buffer(capacity: bytes.count)
      buffer.writeBytes(bytes)
      _ = try? await channel.writeInbound(buffer)
    }

    func sealSubscribe() throws -> Data {
      let message = SecureObservationSubscribe(
        subscriptionID: subscriptionID, resumeCursor: nil)
      return try seal(kind: .observationSubscribe, body: try JSONEncoder().encode(message))
    }

    func sendSubscribe() async throws {
      await writeInbound(try sealSubscribe())
    }

    func sendAcknowledge(cursor: ReplayCursorEnvelope) async throws {
      let message = SecureObservationAcknowledgement(
        subscriptionID: subscriptionID, cursor: cursor)
      await writeInbound(
        try seal(kind: .observationAcknowledge, body: try JSONEncoder().encode(message)))
    }

    func send(kind: ListenerApplicationKind, body: Data) async throws {
      await writeInbound(try seal(kind: kind, body: body))
    }

    func sendRawSealed(_ transform: (Data) -> Data) async throws {
      await writeInbound(transform(try sealSubscribe()))
    }

    func seal(kind: ListenerApplicationKind, body: Data) throws -> Data {
      let envelope = try ListenerApplicationEnvelope(kind: kind, payload: body)
      return try device.outbound.seal(try envelope.encoded())
    }

    func readOutboundBytes() async throws -> Data? {
      guard var buffer = try await channel.readOutbound(as: ByteBuffer.self) else { return nil }
      return buffer.readData(length: buffer.readableBytes)
    }

    func readEnvelope() async throws -> ListenerApplicationEnvelope? {
      guard let bytes = try await readOutboundBytes() else { return nil }
      let plaintext = try device.inbound.open(bytes)
      return try ListenerApplicationEnvelope.decode(plaintext)
    }

    func readDelivery() async throws -> SecureObservationDelivery {
      let decoded = try await readEnvelope()
      let envelope = try XCTUnwrap(decoded)
      XCTAssertEqual(envelope.kind, .observationDelivery)
      return try JSONDecoder().decode(SecureObservationDelivery.self, from: envelope.payload)
    }

    func readCloseReason() async throws -> SecureCloseReason? {
      guard let envelope = try await readEnvelope(), envelope.kind == .closeNotice else {
        return nil
      }
      return try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload).reason
    }
  }
}

/// Deterministic observation seam.
actor FakeListenerObservationHandler: ListenerObservationHandling {
  private var subscribeResult: Result<ListenerObservationBatch, ListenerObservationRefusal>?
  private var pendingBatch: ListenerObservationBatch?
  private(set) var acknowledgements = 0
  private(set) var releases = 0

  func setSubscribeResult(
    _ result: Result<ListenerObservationBatch, ListenerObservationRefusal>
  ) {
    subscribeResult = result
  }

  func setNextBatch(_ batch: ListenerObservationBatch?) {
    pendingBatch = batch
  }

  func subscribe(
    deviceID: UUID,
    subscriptionID: UUID,
    resumeCursor: ReplayCursorEnvelope?
  ) async throws -> ListenerObservationBatch {
    switch subscribeResult {
    case .success(let batch): return batch
    case .failure(let refusal): throw refusal
    case nil: throw ListenerObservationRefusal.notAuthorized
    }
  }

  func nextBatch(deviceID: UUID) async throws -> ListenerObservationBatch? {
    defer { pendingBatch = nil }
    return pendingBatch
  }

  func acknowledge(
    deviceID: UUID,
    subscriptionID: UUID,
    cursor: ReplayCursorEnvelope
  ) async throws {
    acknowledgements += 1
  }

  func release(deviceID: UUID) async {
    releases += 1
  }
}

func assertThrowsErrorAsync<T>(
  _ expression: @autoclosure () async throws -> T,
  file: StaticString = #filePath,
  line: UInt = #line,
  _ handler: (any Error) -> Void = { _ in }
) async {
  do {
    _ = try await expression()
    XCTFail("expected an error", file: file, line: line)
  } catch {
    handler(error)
  }
}
