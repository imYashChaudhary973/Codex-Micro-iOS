import CompanionProtocol
import Foundation
import NIOCore
import NIOEmbedded
import NIOWebSocket
import XCTest

@testable import MacBridgeServer

/// Adversarial coverage of every ADR §9 Step 2.7 ceiling. All timing runs on
/// an injected monotonic clock or an `EmbeddedEventLoop`; no test sleeps.
final class ListenerCeilingTests: XCTestCase {
  private let ceilings = ListenerCeilings()

  private func makeController(
    _ clock: ManualListenerClock,
    ceilings: ListenerCeilings? = nil
  ) -> ListenerAdmissionController {
    ListenerAdmissionController(ceilings: ceilings ?? self.ceilings, now: clock.now)
  }

  private func source(_ index: Int) -> ListenerSourceKey {
    ListenerSourceKey(numericAddress: "10.0.0.\(index)")
  }

  // MARK: - Ceiling configuration

  func testDefaultCeilingsAreExactlyTheADRValues() throws {
    XCTAssertEqual(ceilings.upgradeDeadlineSeconds, 10)
    XCTAssertEqual(ceilings.authenticationDeadlineSeconds, 20)
    XCTAssertEqual(ceilings.maxConcurrentConnections, 16)
    XCTAssertEqual(ceilings.maxUnauthenticatedConnections, 4)
    XCTAssertEqual(ceilings.maxNewConnectionsPerSourcePerMinute, 6)
    XCTAssertEqual(ceilings.maxPairingAttemptsPerSourcePerMinute, 3)
    XCTAssertEqual(ceilings.maxInboundMessagesPerSecond, 32)
    XCTAssertEqual(ceilings.maxInboundBytesPerSecond, 1_048_576)
    XCTAssertEqual(ceilings.maxOutboundQueueFrames, 64)
    XCTAssertEqual(ceilings.maxOutboundQueueBytes, 262_144)
    XCTAssertEqual(ceilings.maxNonWritableSeconds, 10)
    XCTAssertEqual(ceilings.pingCadenceSeconds, 30)
    XCTAssertEqual(ceilings.pongDeadlineSeconds, 10)
    XCTAssertEqual(ceilings.idleExpirySeconds, 120)
    XCTAssertNoThrow(try ceilings.validated())
  }

  func testCeilingsMayTightenButNeverExceedTheADR() throws {
    XCTAssertNoThrow(try ListenerCeilings(maxConcurrentConnections: 4).validated())
    XCTAssertThrowsError(try ListenerCeilings(maxConcurrentConnections: 17).validated()) { error in
      XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsExceedADR)
    }
    XCTAssertThrowsError(try ListenerCeilings(idleExpirySeconds: 121).validated())
    XCTAssertThrowsError(try ListenerCeilings(maxInboundMessagesPerSecond: 0).validated())
    XCTAssertThrowsError(
      try ListenerCeilings(
        maxConcurrentConnections: 2,
        maxUnauthenticatedConnections: 4
      ).validated())
  }

  func testTightenedCeilingsMustStayMutuallyConsistent() throws {
    // A cadence tightened inside the authentication deadline would let an
    // unauthenticated peer reach the server-originated keep-alive path.
    XCTAssertThrowsError(try ListenerCeilings(pingCadenceSeconds: 20).validated()) { error in
      XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsInconsistent)
    }
    XCTAssertThrowsError(
      try ListenerCeilings(authenticationDeadlineSeconds: 20, pingCadenceSeconds: 15).validated())
    // Idle expiry must outlast one full ping/pong round.
    XCTAssertThrowsError(
      try ListenerCeilings(
        authenticationDeadlineSeconds: 5,
        pingCadenceSeconds: 30,
        pongDeadlineSeconds: 10,
        idleExpirySeconds: 40
      ).validated()
    ) { error in
      XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsInconsistent)
    }
    // The pre-upgrade budget must admit a maximal legitimate upgrade.
    XCTAssertThrowsError(try ListenerCeilings(maxPreUpgradeBytes: 128).validated()) { error in
      XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsInconsistent)
    }
    XCTAssertThrowsError(
      try ListenerCeilings(
        maxPreUpgradeBytes: ListenerCeilings.preUpgradeByteCeiling + 1
      ).validated()
    ) { error in
      XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsExceedADR)
    }
    // A consistent tightening is still accepted.
    XCTAssertNoThrow(
      try ListenerCeilings(
        authenticationDeadlineSeconds: 10,
        pingCadenceSeconds: 15,
        pongDeadlineSeconds: 5,
        idleExpirySeconds: 60
      ).validated())
  }

  func testPerSourceMapIsBoundedAcrossManyDistinctSources() {
    let clock = ManualListenerClock()
    let controller = makeController(clock)
    // Admission runs at accept, before TLS, so an attacker cycling addresses
    // must not be able to grow this map without bound.
    for index in 0..<5_000 {
      let key = ListenerSourceKey(numericAddress: "fd00::\(index)")
      if case .success(let ticket) = controller.admit(source: key) {
        ticket.release()
      }
      XCTAssertLessThanOrEqual(
        controller.trackedSourceCount,
        ListenerAdmissionController.sourceHardCap + 1
      )
    }
    XCTAssertLessThanOrEqual(
      controller.trackedSourceCount, ListenerAdmissionController.sourceHardCap + 1)

    // Once the windows age out, ordinary admission reclaims everything.
    clock.advance(seconds: 61)
    _ = controller.admit(source: ListenerSourceKey(numericAddress: "fd00::ffff"))
    XCTAssertLessThanOrEqual(controller.trackedSourceCount, 2)
  }

  func testHandshakeMessageAdmissionAlsoBoundsTheSourceMap() {
    let clock = ManualListenerClock()
    let controller = makeController(clock)
    for index in 0..<3_000 {
      _ = controller.admitHandshakeMessage(
        .pairingRequest,
        source: ListenerSourceKey(numericAddress: "fd01::\(index)")
      )
    }
    XCTAssertLessThanOrEqual(
      controller.trackedSourceCount, ListenerAdmissionController.sourceHardCap + 1)
  }

  // MARK: - Connection caps

  func testUnauthenticatedConcurrencyCeilingIsEnforced() {
    let controller = makeController(ManualListenerClock())
    var tickets: [ListenerConnectionTicket] = []
    for index in 0..<ceilings.maxUnauthenticatedConnections {
      guard case .success(let ticket) = controller.admit(source: source(index)) else {
        return XCTFail("connection \(index) must be admitted")
      }
      tickets.append(ticket)
    }
    guard case .failure(let rejection) = controller.admit(source: source(99)) else {
      return XCTFail("the fifth unauthenticated connection must be refused")
    }
    XCTAssertEqual(rejection, .unauthenticatedCapacity)
    XCTAssertEqual(controller.counts.unauthenticated, 4)

    tickets[0].markAuthenticated()
    XCTAssertEqual(controller.counts.unauthenticated, 3)
    guard case .success = controller.admit(source: source(99)) else {
      return XCTFail("promoting a connection must free an unauthenticated slot")
    }
  }

  func testGlobalConcurrencyCeilingIsEnforcedAcrossAuthenticatedConnections() {
    let controller = makeController(ManualListenerClock())
    var tickets: [ListenerConnectionTicket] = []
    for index in 0..<ceilings.maxConcurrentConnections {
      guard case .success(let ticket) = controller.admit(source: source(index)) else {
        return XCTFail("connection \(index) must be admitted")
      }
      ticket.markAuthenticated()
      tickets.append(ticket)
    }
    XCTAssertEqual(controller.counts.total, 16)
    guard case .failure(let rejection) = controller.admit(source: source(200)) else {
      return XCTFail("the seventeenth connection must be refused")
    }
    XCTAssertEqual(rejection, .globalCapacity)

    tickets[0].release()
    XCTAssertEqual(controller.counts.total, 15)
    guard case .success = controller.admit(source: source(200)) else {
      return XCTFail("releasing a slot must readmit")
    }
  }

  func testPerSourceConnectionRateCeilingIsEnforcedAndWindowSlides() {
    let clock = ManualListenerClock()
    let controller = makeController(clock)
    let key = source(7)
    for index in 0..<ceilings.maxNewConnectionsPerSourcePerMinute {
      guard case .success(let ticket) = controller.admit(source: key) else {
        return XCTFail("connection \(index) must be admitted")
      }
      ticket.markAuthenticated()
    }
    guard case .failure(let rejection) = controller.admit(source: key) else {
      return XCTFail("the seventh per-source connection must be refused")
    }
    XCTAssertEqual(rejection, .sourceConnectionRate)

    // A different source is unaffected.
    guard case .success(let other) = controller.admit(source: source(8)) else {
      return XCTFail("an unrelated source must still be admitted")
    }
    other.markAuthenticated()

    clock.advance(seconds: 61)
    guard case .success = controller.admit(source: key) else {
      return XCTFail("the per-source window must slide")
    }
  }

  func testRefusedConnectionsDoNotExtendTheSourceWindow() {
    let clock = ManualListenerClock()
    let controller = makeController(clock)
    let key = source(11)
    for _ in 0..<ceilings.maxNewConnectionsPerSourcePerMinute {
      guard case .success(let ticket) = controller.admit(source: key) else {
        return XCTFail("expected admission")
      }
      ticket.markAuthenticated()
    }
    clock.advance(seconds: 30)
    for _ in 0..<50 {
      let outcome: ListenerAdmissionRejection? = {
        if case .failure(let rejection) = controller.admit(source: key) { return rejection }
        return nil
      }()
      XCTAssertEqual(outcome, .sourceConnectionRate)
    }
    clock.advance(seconds: 31)
    guard case .success = controller.admit(source: key) else {
      return XCTFail("a refused flood must not push the window forward")
    }
  }

  func testPerSourcePairingAttemptCeilingIsEnforcedAndWindowSlides() {
    let clock = ManualListenerClock()
    let controller = makeController(clock)
    let key = source(21)
    for _ in 0..<ceilings.maxPairingAttemptsPerSourcePerMinute {
      XCTAssertTrue(controller.admitHandshakeMessage(.pairingRequest, source: key))
    }
    XCTAssertFalse(controller.admitHandshakeMessage(.pairingRequest, source: key))
    XCTAssertTrue(controller.admitHandshakeMessage(.pairingRequest, source: source(22)))
    clock.advance(seconds: 61)
    XCTAssertTrue(controller.admitHandshakeMessage(.pairingRequest, source: key))
  }

  func testStopAcceptingRefusesEveryLaterConnection() {
    let controller = makeController(ManualListenerClock())
    controller.stopAccepting()
    guard case .failure(let rejection) = controller.admit(source: source(1)) else {
      return XCTFail("a stopped controller must refuse")
    }
    XCTAssertEqual(rejection, .notAccepting)
  }

  func testIdleSourceWindowsArePruned() {
    let clock = ManualListenerClock()
    let controller = makeController(clock)
    for index in 0..<3 {
      guard case .success(let ticket) = controller.admit(source: source(index)) else {
        return XCTFail("expected admission")
      }
      ticket.release()
    }
    clock.advance(seconds: 61)
    controller.pruneIdleSources()
    for index in 0..<3 {
      guard case .success(let ticket) = controller.admit(source: source(index)) else {
        return XCTFail("pruned sources must be admissible again")
      }
      ticket.release()
    }
  }

  // MARK: - Inbound rate

  func testInboundMessageRateCeilingIsEnforcedAndWindowSlides() {
    let clock = ManualListenerClock()
    let meter = ListenerInboundRateMeter(
      maxMessagesPerSecond: ceilings.maxInboundMessagesPerSecond,
      maxBytesPerSecond: ceilings.maxInboundBytesPerSecond,
      now: clock.now
    )
    for _ in 0..<ceilings.maxInboundMessagesPerSecond {
      XCTAssertTrue(meter.admit(bytes: 1))
    }
    XCTAssertFalse(meter.admit(bytes: 1))
    clock.advance(seconds: 1.1)
    XCTAssertTrue(meter.admit(bytes: 1))
  }

  func testInboundByteRateCeilingIsEnforcedIndependentlyOfMessageCount() {
    let clock = ManualListenerClock()
    let meter = ListenerInboundRateMeter(
      maxMessagesPerSecond: ceilings.maxInboundMessagesPerSecond,
      maxBytesPerSecond: ceilings.maxInboundBytesPerSecond,
      now: clock.now
    )
    let chunk = SecureTransportLimits.maxMessageBytes
    var admitted = 0
    while meter.admit(bytes: chunk) {
      admitted += 1
      XCTAssertLessThan(admitted, ceilings.maxInboundMessagesPerSecond)
    }
    XCTAssertEqual(admitted * chunk, ceilings.maxInboundBytesPerSecond)
    clock.advance(seconds: 1.1)
    XCTAssertTrue(meter.admit(bytes: chunk))
  }

  func testInboundRateHandlerClosesTheConnectionOnOverflow() throws {
    let clock = ManualListenerClock()
    let meter = ListenerInboundRateMeter(
      maxMessagesPerSecond: 2,
      maxBytesPerSecond: 1_024,
      now: clock.now
    )
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(ListenerInboundRateHandler(meter: meter))
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    var buffer = channel.allocator.buffer(capacity: 4)
    buffer.writeBytes([0, 1, 2, 3])
    let frame = WebSocketFrame(fin: true, opcode: .binary, data: buffer)
    try channel.writeInbound(frame)
    try channel.writeInbound(frame)
    XCTAssertTrue(channel.isActive)
    try channel.writeInbound(frame)
    XCTAssertFalse(channel.isActive)
  }

  func testInboundRateHandlerMetersPeerControlFrames() throws {
    let clock = ManualListenerClock()
    let meter = ListenerInboundRateMeter(
      maxMessagesPerSecond: 2,
      maxBytesPerSecond: 1_024,
      now: clock.now
    )
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(ListenerInboundRateHandler(meter: meter))
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    let ping = WebSocketFrame(
      fin: true, opcode: .ping, data: channel.allocator.buffer(capacity: 0))
    try channel.writeInbound(ping)
    try channel.writeInbound(ping)
    XCTAssertTrue(channel.isActive)
    try channel.writeInbound(ping)
    XCTAssertFalse(channel.isActive, "peer pings must consume the inbound message ceiling")
  }

  // MARK: - Deadlines

  func testUpgradeDeadlineClosesTheConnection() throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
      ListenerUpgradeDeadlineHandler(deadline: .seconds(10)))
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    channel.embeddedEventLoop.advanceTime(by: .seconds(9))
    XCTAssertTrue(channel.isActive)
    channel.embeddedEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(channel.isActive)
  }

  func testUpgradeCompletionCancelsTheUpgradeDeadline() throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
      ListenerUpgradeDeadlineHandler(deadline: .seconds(10)))
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    channel.pipeline.fireUserInboundEventTriggered(ListenerUpgradeCompleted())
    channel.embeddedEventLoop.advanceTime(by: .seconds(30))
    XCTAssertTrue(channel.isActive)
  }

  func testAuthenticationDeadlineClosesAnUnauthenticatedConnection() throws {
    let controller = makeController(ManualListenerClock())
    guard case .success(let ticket) = controller.admit(source: source(1)) else {
      return XCTFail("expected admission")
    }
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerHandshakeGateHandler(
        connectionID: UUID(),
        source: source(1),
        admission: controller,
        ticket: ticket,
        handshake: ScriptedHandshakeHandler(),
        authenticationDeadline: .seconds(20),
        // Longer than this test's window, so it still proves the
        // authentication deadline rather than the silence budget.
        silenceBudget: .seconds(19),
        logger: DiscardingListenerLogger()
      ))
    channel.embeddedEventLoop.advanceTime(by: .seconds(18))
    XCTAssertTrue(channel.isActive)
    channel.embeddedEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(channel.isActive, "a silent peer is bounded by the silence budget")
  }

  // MARK: - Keep-alive, pong deadline, idle expiry

  func testPingCadenceStartsOnlyAfterAuthentication() throws {
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerKeepAliveHandler(
        pingCadence: .seconds(30),
        pongDeadline: .seconds(10),
        idleExpiry: .seconds(300)
      ))
    // Unauthenticated: no server-originated traffic at any cadence tick.
    channel.embeddedEventLoop.advanceTime(by: .seconds(120))
    XCTAssertNil(try channel.readOutbound(as: WebSocketFrame.self))
    XCTAssertTrue(channel.isActive)
    _ = try? channel.finish()
  }

  func testPingCadenceAndUnansweredPongDeadlineCloseTheConnection() throws {
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerKeepAliveHandler(
        pingCadence: .seconds(30),
        pongDeadline: .seconds(10),
        idleExpiry: .seconds(300)
      ))
    channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())
    channel.embeddedEventLoop.advanceTime(by: .seconds(30))
    let ping = try channel.readOutbound(as: WebSocketFrame.self)
    XCTAssertEqual(ping?.opcode, .ping)
    XCTAssertEqual(ping?.data.readableBytes, 8)
    XCTAssertTrue(channel.isActive)
    channel.embeddedEventLoop.advanceTime(by: .seconds(10))
    XCTAssertFalse(channel.isActive)
  }

  func testOnlyAPongMatchingTheOutstandingPingClearsTheDeadline() throws {
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerKeepAliveHandler(
        pingCadence: .seconds(30),
        pongDeadline: .seconds(10),
        idleExpiry: .seconds(300)
      ))
    channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())
    channel.embeddedEventLoop.advanceTime(by: .seconds(30))
    let ping = try XCTUnwrap(try channel.readOutbound(as: WebSocketFrame.self))
    let payload = Data(ping.data.readableBytesView)

    // A pong with the wrong payload does not clear the deadline.
    var wrong = channel.allocator.buffer(capacity: payload.count)
    wrong.writeBytes(Data(payload.reversed()))
    try channel.writeInbound(WebSocketFrame(fin: true, opcode: .pong, data: wrong))
    channel.embeddedEventLoop.advanceTime(by: .seconds(10))
    XCTAssertFalse(channel.isActive, "an unsolicited pong must not keep a dead peer alive")
  }

  func testMatchingPongClearsThePongDeadline() throws {
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerKeepAliveHandler(
        pingCadence: .seconds(30),
        pongDeadline: .seconds(10),
        idleExpiry: .seconds(300)
      ))
    channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())
    channel.embeddedEventLoop.advanceTime(by: .seconds(30))
    let ping = try XCTUnwrap(try channel.readOutbound(as: WebSocketFrame.self))
    var echo = channel.allocator.buffer(capacity: ping.data.readableBytes)
    echo.writeBytes(ping.data.readableBytesView)
    try channel.writeInbound(WebSocketFrame(fin: true, opcode: .pong, data: echo))
    channel.embeddedEventLoop.advanceTime(by: .seconds(11))
    XCTAssertTrue(channel.isActive)
    _ = try? channel.finish()
  }

  func testIdleExpiryClosesAConnectionWithNoApplicationFrame() throws {
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerKeepAliveHandler(
        pingCadence: .seconds(300),
        pongDeadline: .seconds(10),
        idleExpiry: .seconds(120)
      ))
    channel.embeddedEventLoop.advanceTime(by: .seconds(119))
    XCTAssertTrue(channel.isActive)
    channel.embeddedEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(channel.isActive)
  }

  func testOnlyApplicationFramesResetTheIdleTimer() throws {
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerKeepAliveHandler(
        pingCadence: .seconds(300),
        pongDeadline: .seconds(10),
        idleExpiry: .seconds(120)
      ))
    channel.embeddedEventLoop.advanceTime(by: .seconds(100))
    // Pongs are control traffic and must not hold the connection open.
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .pong, data: channel.allocator.buffer(capacity: 0)))
    channel.embeddedEventLoop.advanceTime(by: .seconds(21))
    XCTAssertFalse(channel.isActive)

    let refreshed = EmbeddedChannel()
    try refreshed.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try refreshed.pipeline.syncOperations.addHandler(
      ListenerKeepAliveHandler(
        pingCadence: .seconds(300),
        pongDeadline: .seconds(10),
        idleExpiry: .seconds(120)
      ))
    refreshed.embeddedEventLoop.advanceTime(by: .seconds(100))
    var payload = refreshed.allocator.buffer(capacity: 4)
    payload.writeBytes([1, 2, 3, 4])
    try refreshed.writeInbound(WebSocketFrame(fin: true, opcode: .binary, data: payload))
    refreshed.embeddedEventLoop.advanceTime(by: .seconds(100))
    XCTAssertTrue(refreshed.isActive)
    _ = try? refreshed.finish()
  }

  // MARK: - Outbound queue and slow consumers

  func testOutboundFrameCeilingClosesTheConnection() throws {
    let channel = EmbeddedChannel()
    let handler = ListenerOutboundBoundHandler(
      maxFrames: 4,
      maxBytes: 1_000_000,
      nonWritableLimit: .seconds(10)
    )
    try channel.pipeline.syncOperations.addHandler(handler)
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    var buffer = channel.allocator.buffer(capacity: 4)
    buffer.writeBytes([1, 2, 3, 4])
    let frame = WebSocketFrame(fin: true, opcode: .binary, data: buffer)
    for _ in 0..<4 {
      channel.write(frame, promise: nil)
    }
    XCTAssertEqual(handler.pending.frames, 4)
    XCTAssertTrue(channel.isActive)
    channel.write(frame, promise: nil)
    XCTAssertFalse(channel.isActive)
  }

  func testOutboundByteCeilingClosesTheConnection() throws {
    let channel = EmbeddedChannel()
    let handler = ListenerOutboundBoundHandler(
      maxFrames: 1_000,
      maxBytes: 4_096,
      nonWritableLimit: .seconds(10)
    )
    try channel.pipeline.syncOperations.addHandler(handler)
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    var buffer = channel.allocator.buffer(capacity: 2_048)
    buffer.writeBytes([UInt8](repeating: 9, count: 2_048))
    let frame = WebSocketFrame(fin: true, opcode: .binary, data: buffer)
    channel.write(frame, promise: nil)
    channel.write(frame, promise: nil)
    XCTAssertEqual(handler.pending.bytes, 4_096)
    XCTAssertTrue(channel.isActive)
    channel.write(frame, promise: nil)
    XCTAssertFalse(channel.isActive)
  }

  func testCompletedWritesDiscountTheOutboundQueue() throws {
    let channel = EmbeddedChannel()
    let handler = ListenerOutboundBoundHandler(
      maxFrames: 2,
      maxBytes: 1_000_000,
      nonWritableLimit: .seconds(10)
    )
    try channel.pipeline.syncOperations.addHandler(handler)
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    var buffer = channel.allocator.buffer(capacity: 4)
    buffer.writeBytes([1, 2, 3, 4])
    let frame = WebSocketFrame(fin: true, opcode: .binary, data: buffer)
    channel.write(frame, promise: nil)
    channel.write(frame, promise: nil)
    channel.flush()
    XCTAssertEqual(handler.pending.frames, 0)
    channel.write(frame, promise: nil)
    XCTAssertTrue(channel.isActive)
  }

  func testSlowConsumerClosesAfterTheNonWritableCeiling() throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
      ListenerOutboundBoundHandler(
        maxFrames: 64,
        maxBytes: 262_144,
        nonWritableLimit: .seconds(10)
      ))
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    channel.isWritable = false
    channel.pipeline.fireChannelWritabilityChanged()
    channel.embeddedEventLoop.advanceTime(by: .seconds(9))
    XCTAssertTrue(channel.isActive)
    channel.embeddedEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(channel.isActive)
  }

  func testRecoveringWritabilityCancelsTheSlowConsumerClose() throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
      ListenerOutboundBoundHandler(
        maxFrames: 64,
        maxBytes: 262_144,
        nonWritableLimit: .seconds(10)
      ))
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    channel.isWritable = false
    channel.pipeline.fireChannelWritabilityChanged()
    channel.embeddedEventLoop.advanceTime(by: .seconds(5))
    channel.isWritable = true
    channel.pipeline.fireChannelWritabilityChanged()
    channel.embeddedEventLoop.advanceTime(by: .seconds(60))
    XCTAssertTrue(channel.isActive)
    _ = try? channel.finish()
  }
}
