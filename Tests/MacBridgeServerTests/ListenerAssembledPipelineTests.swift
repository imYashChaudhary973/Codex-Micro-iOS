import CompanionProtocol
import Foundation
import NIOCore
import NIOEmbedded
import NIOWebSocket
import XCTest

@testable import MacBridgeServer

/// Coverage of the **assembled** post-upgrade pipeline, built through the
/// same public entry point production uses (``ListenerPipeline/configureWebSocket(channel:connectionID:source:admission:ticket:rejections:logger:handshake:ceilings:now:)``).
///
/// Testing each handler alone hides ordering defects: a write that travels
/// the wrong way, a meter that sits behind the handler consuming the frames
/// it should meter, or an event swallowed before a downstream consumer sees
/// it. Every assertion here is about the composition, not the parts.
final class ListenerAssembledPipelineTests: XCTestCase {
  private struct Harness {
    let channel: EmbeddedChannel
    let logger: InMemoryListenerLogger
    let handshake: ScriptedHandshakeHandler
    let controller: ListenerAdmissionController
    let clock: ManualListenerClock
  }

  private func assemble(
    ceilings: ListenerCeilings = ListenerCeilings(),
    handshake: ScriptedHandshakeHandler = ScriptedHandshakeHandler()
  ) throws -> Harness {
    let clock = ManualListenerClock()
    let logger = InMemoryListenerLogger()
    let controller = ListenerAdmissionController(ceilings: ceilings, now: clock.now)
    let source = ListenerSourceKey(numericAddress: "10.0.0.90")
    guard case .success(let ticket) = controller.admit(source: source) else {
      throw StubPrerequisiteFailure()
    }
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try ListenerPipeline.configureWebSocket(
      channel: channel,
      connectionID: UUID(),
      source: source,
      admission: controller,
      ticket: ticket,
      rejections: ListenerRejectionRecorder(),
      logger: logger,
      handshake: handshake,
      ceilings: ceilings,
      now: clock.now
    ).wait()
    channel.pipeline.fireUserInboundEventTriggered(ListenerUpgradeCompleted())
    return Harness(
      channel: channel,
      logger: logger,
      handshake: handshake,
      controller: controller,
      clock: clock
    )
  }

  private func frame(
    _ opcode: WebSocketOpcode,
    bytes: Int,
    in channel: EmbeddedChannel
  ) -> WebSocketFrame {
    var buffer = channel.allocator.buffer(capacity: bytes)
    buffer.writeBytes([UInt8](repeating: 0x2B, count: bytes))
    return WebSocketFrame(fin: true, opcode: opcode, data: buffer)
  }

  // MARK: - Server ping actually reaches the peer

  func testServerPingReachesThePeerThroughTheAssembledPipeline() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    harness.channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())

    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(30))
    let ping = try XCTUnwrap(try harness.channel.readOutbound(as: WebSocketFrame.self))
    XCTAssertEqual(ping.opcode, .ping)
    XCTAssertEqual(ping.data.readableBytes, 8)
    XCTAssertTrue(harness.channel.isActive)
  }

  func testMissingPongClosesWithinTheDeadlineThroughTheAssembledPipeline() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    harness.channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())

    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(30))
    XCTAssertEqual(
      try harness.channel.readOutbound(as: WebSocketFrame.self)?.opcode, .ping)
    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(9))
    XCTAssertTrue(harness.channel.isActive)
    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(harness.channel.isActive)
    XCTAssertEqual(harness.logger.count(of: .pongDeadlineElapsed), 1)
  }

  func testMatchingPongKeepsTheAssembledConnectionAlive() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    harness.channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())

    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(30))
    let ping = try XCTUnwrap(try harness.channel.readOutbound(as: WebSocketFrame.self))
    var echo = harness.channel.allocator.buffer(capacity: ping.data.readableBytes)
    echo.writeBytes(ping.data.readableBytesView)
    try harness.channel.writeInbound(WebSocketFrame(fin: true, opcode: .pong, data: echo))
    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(11))
    XCTAssertTrue(harness.channel.isActive)
  }

  func testNoServerTrafficIsEmittedBeforeAuthentication() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    // The authentication deadline closes first; no ping is ever emitted.
    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(20))
    XCTAssertFalse(harness.channel.isActive)
    XCTAssertNil(try harness.channel.readOutbound(as: WebSocketFrame.self))
    XCTAssertEqual(harness.logger.count(of: .authenticationDeadlineElapsed), 1)
  }

  // MARK: - Control frames are metered and accounted

  func testPeerPingsConsumeTheInboundMessageCeiling() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    let ceiling = ListenerCeilings().maxInboundMessagesPerSecond
    for _ in 0..<ceiling {
      try harness.channel.writeInbound(frame(.ping, bytes: 0, in: harness.channel))
    }
    XCTAssertTrue(harness.channel.isActive)
    try harness.channel.writeInbound(frame(.ping, bytes: 0, in: harness.channel))
    XCTAssertFalse(harness.channel.isActive, "a ping flood must hit the inbound ceiling")
    XCTAssertEqual(harness.logger.count(of: .inboundRateExceeded), 1)
  }

  func testPeerPingsConsumeTheInboundByteCeiling() throws {
    let ceilings = ListenerCeilings(maxInboundBytesPerSecond: 256)
    let harness = try assemble(ceilings: ceilings)
    defer { _ = try? harness.channel.finish() }
    for _ in 0..<2 {
      try harness.channel.writeInbound(frame(.ping, bytes: 125, in: harness.channel))
    }
    XCTAssertTrue(harness.channel.isActive)
    try harness.channel.writeInbound(frame(.ping, bytes: 125, in: harness.channel))
    XCTAssertFalse(harness.channel.isActive)
  }

  func testPongRepliesCountTowardTheOutboundQueueBound() throws {
    // A single pong larger than the whole outbound byte bound must be
    // refused. If the pong bypassed the accounting handler — as it did while
    // the bound sat tail-ward of the frame policy — this would sail through.
    let ceilings = ListenerCeilings(maxOutboundQueueBytes: 4)
    let harness = try assemble(ceilings: ceilings)
    defer { _ = try? harness.channel.finish() }
    try harness.channel.writeInbound(frame(.ping, bytes: 8, in: harness.channel))
    XCTAssertFalse(harness.channel.isActive, "pongs must be accounted, not free")
    XCTAssertEqual(harness.logger.count(of: .outboundQueueExceeded), 1)
  }

  func testApplicationWritesAndPongsShareTheSameOutboundAccounting() throws {
    let ceilings = ListenerCeilings(maxOutboundQueueBytes: 4)
    let harness = try assemble(ceilings: ceilings)
    defer { _ = try? harness.channel.finish() }
    // An application payload written from the tail crosses the very same
    // accounting handler a pong does, so the same bound applies to both.
    var buffer = harness.channel.allocator.buffer(capacity: 8)
    buffer.writeBytes([UInt8](repeating: 0x09, count: 8))
    harness.channel.writeAndFlush(buffer, promise: nil)
    XCTAssertFalse(harness.channel.isActive, "an oversized application write is refused too")
    XCTAssertEqual(harness.logger.count(of: .outboundQueueExceeded), 1)
  }

  func testFivethousandPingsCannotBeAcceptedWithDefaultCeilings() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    var accepted = 0
    for _ in 0..<5_000 {
      guard harness.channel.isActive else { break }
      try harness.channel.writeInbound(frame(.ping, bytes: 0, in: harness.channel))
      accepted += 1
    }
    XCTAssertLessThanOrEqual(accepted, ListenerCeilings().maxInboundMessagesPerSecond + 1)
    XCTAssertFalse(harness.channel.isActive)
  }

  // MARK: - Application traffic still crosses every bound

  func testApplicationBytesLeaveAsSingleBinaryFramesThroughTheWholeChain() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    var buffer = harness.channel.allocator.buffer(capacity: 24)
    buffer.writeBytes([UInt8](repeating: 0x7C, count: 24))
    harness.channel.writeAndFlush(buffer, promise: nil)

    let frame = try XCTUnwrap(try harness.channel.readOutbound(as: WebSocketFrame.self))
    XCTAssertEqual(frame.opcode, .binary)
    XCTAssertTrue(frame.fin)
    XCTAssertEqual(frame.data.readableBytes, 24)
    XCTAssertTrue(harness.channel.isActive)
  }

  func testInboundApplicationBytesReachTheGateAsBytes() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    // A malformed application message is refused at the gate, which proves
    // the frame → bytes boundary and the allowlist both sit downstream of
    // every bound in the chain.
    var buffer = harness.channel.allocator.buffer(capacity: 64)
    buffer.writeBytes(Data(#"{"kind":"applicationCommand","payload":"AAAA"}"#.utf8))
    try harness.channel.writeInbound(WebSocketFrame(fin: true, opcode: .binary, data: buffer))

    let written = try XCTUnwrap(try harness.channel.readOutbound(as: WebSocketFrame.self))
    XCTAssertEqual(written.opcode, .binary)
    let envelope = try ListenerHandshakeEnvelope.decode(Data(written.data.readableBytesView))
    XCTAssertEqual(envelope.kind, .closeNotice)
    let notice = try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload)
    XCTAssertEqual(notice.reason, ListenerPreAuthAllowlist.collapsedRefusal)
    XCTAssertEqual(harness.logger.count(of: .preAuthMessageRejected), 1)
  }

  func testTextFramesAreRejectedByTheAssembledPipeline() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    try harness.channel.writeInbound(frame(.text, bytes: 8, in: harness.channel))
    XCTAssertFalse(harness.channel.isActive)
    XCTAssertEqual(harness.logger.count(of: .frameRejected), 1)
  }

  func testIdleExpiryStillAppliesToAnAnsweringPeerInTheAssembledPipeline() throws {
    let harness = try assemble()
    defer { _ = try? harness.channel.finish() }
    harness.channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())

    // The peer answers every ping, so only the application idle timer can
    // close it: liveness at the control level is not liveness at the
    // application level.
    for _ in 0..<3 {
      harness.channel.embeddedEventLoop.advanceTime(by: .seconds(30))
      let ping = try XCTUnwrap(try harness.channel.readOutbound(as: WebSocketFrame.self))
      var echo = harness.channel.allocator.buffer(capacity: ping.data.readableBytes)
      echo.writeBytes(ping.data.readableBytesView)
      try harness.channel.writeInbound(WebSocketFrame(fin: true, opcode: .pong, data: echo))
      XCTAssertTrue(harness.channel.isActive)
    }
    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(29))
    XCTAssertTrue(harness.channel.isActive)
    harness.channel.embeddedEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(harness.channel.isActive)
    XCTAssertEqual(harness.logger.count(of: .idleExpired), 1)
  }

  // MARK: - Upgrade completion is observable downstream

  func testUpgradeCompletionReachesDownstreamHandlersBeforeRemoval() throws {
    final class EventRecorder: ChannelInboundHandler, @unchecked Sendable {
      typealias InboundIn = NIOAny
      private let lock = NSLock()
      private var seen = 0

      var upgradeEvents: Int { lock.withLock { seen } }

      func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is ListenerUpgradeCompleted {
          lock.withLock { seen += 1 }
        }
        context.fireUserInboundEventTriggered(event)
      }
    }

    let channel = EmbeddedChannel()
    let recorder = EventRecorder()
    try channel.pipeline.syncOperations.addHandler(
      ListenerUpgradeDeadlineHandler(deadline: .seconds(10)))
    try channel.pipeline.syncOperations.addHandler(recorder)
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()

    channel.pipeline.fireUserInboundEventTriggered(ListenerUpgradeCompleted())
    XCTAssertEqual(recorder.upgradeEvents, 1, "the event must not be swallowed by removal")
    // The deadline handler removed itself, so its timer can no longer fire.
    channel.embeddedEventLoop.advanceTime(by: .seconds(60))
    XCTAssertTrue(channel.isActive)
    _ = try? channel.finish()
  }

  func testAuthenticationDeadlineStartsFromTheUpgradeEventAlone() throws {
    let controller = ListenerAdmissionController(ceilings: ListenerCeilings())
    let source = ListenerSourceKey(numericAddress: "10.0.0.91")
    guard case .success(let ticket) = controller.admit(source: source) else {
      return XCTFail("expected admission")
    }
    let channel = EmbeddedChannel()
    let gate = ListenerHandshakeGateHandler(
      connectionID: UUID(),
      source: source,
      admission: controller,
      ticket: ticket,
      handshake: ScriptedHandshakeHandler(),
      authenticationDeadline: .seconds(20),
      logger: DiscardingListenerLogger()
    )
    // Added while inactive, so only the upgrade event can start the deadline.
    try channel.pipeline.syncOperations.addHandler(gate)
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    channel.pipeline.fireUserInboundEventTriggered(ListenerUpgradeCompleted())
    channel.embeddedEventLoop.advanceTime(by: .seconds(19))
    XCTAssertTrue(channel.isActive)
    channel.embeddedEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(channel.isActive)
  }

  // MARK: - Pre-upgrade byte budget

  func testPreUpgradeByteBudgetClosesAFloodingConnection() throws {
    let logger = InMemoryListenerLogger()
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
      ListenerPreUpgradeByteLimitHandler(maximumBytes: 1_024) {
        logger.record(.preUpgradeBudgetExceeded)
      })
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()

    var buffer = channel.allocator.buffer(capacity: 512)
    buffer.writeBytes([UInt8](repeating: 0x41, count: 512))
    try channel.writeInbound(buffer)
    try channel.writeInbound(buffer)
    XCTAssertTrue(channel.isActive)
    try channel.writeInbound(buffer)
    XCTAssertFalse(channel.isActive)
    XCTAssertEqual(logger.count(of: .preUpgradeBudgetExceeded), 1)
  }

  func testPreUpgradeLimiterRemovesItselfOnUpgradeAndForwardsTheEvent() throws {
    let channel = EmbeddedChannel()
    let limiter = ListenerPreUpgradeByteLimitHandler(maximumBytes: 16)
    try channel.pipeline.syncOperations.addHandler(limiter)
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    channel.pipeline.fireUserInboundEventTriggered(ListenerUpgradeCompleted())

    // Post-upgrade traffic is no longer counted by this handler.
    var buffer = channel.allocator.buffer(capacity: 64)
    buffer.writeBytes([UInt8](repeating: 0x41, count: 64))
    try channel.writeInbound(buffer)
    XCTAssertTrue(channel.isActive)
    XCTAssertEqual(limiter.receivedBytes, 0)
    _ = try? channel.finish()
  }
}
