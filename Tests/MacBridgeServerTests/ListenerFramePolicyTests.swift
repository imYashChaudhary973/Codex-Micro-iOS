import CompanionProtocol
import Foundation
import NIOCore
import NIOEmbedded
import NIOWebSocket
import XCTest

@testable import MacBridgeServer

/// Frame policy matrix (ADR §9). Every case runs on an `EmbeddedChannel`, so
/// nothing depends on wall-clock time or a real socket.
final class ListenerFramePolicyTests: XCTestCase {
  private final class ViolationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [ListenerFrameViolation] = []

    func record(_ violation: ListenerFrameViolation) {
      lock.withLock { storage.append(violation) }
    }

    var violations: [ListenerFrameViolation] {
      lock.withLock { storage }
    }
  }

  private func makeChannel() -> (EmbeddedChannel, ViolationBox) {
    let box = ViolationBox()
    let channel = EmbeddedChannel()
    let recorder: @Sendable (ListenerFrameViolation) -> Void = { box.record($0) }
    XCTAssertNoThrow(
      try channel.pipeline.syncOperations.addHandlers([
        ListenerFragmentAggregator(onViolation: recorder),
        ListenerBinaryFramePolicy(onViolation: recorder),
      ]))
    XCTAssertNoThrow(try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait())
    return (channel, box)
  }

  private func buffer(_ byteCount: Int, in channel: EmbeddedChannel) -> ByteBuffer {
    var buffer = channel.allocator.buffer(capacity: byteCount)
    buffer.writeBytes([UInt8](repeating: 0x7F, count: byteCount))
    return buffer
  }

  func testSingleBinaryFrameReachesTheApplicationAsBytes() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    let payload = buffer(64, in: channel)
    try channel.writeInbound(WebSocketFrame(fin: true, opcode: .binary, data: payload))
    let received = try channel.readInbound(as: ByteBuffer.self)
    XCTAssertEqual(received?.readableBytes, 64)
    XCTAssertTrue(box.violations.isEmpty)
  }

  func testTextFramesAreRejected() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    let payload = buffer(8, in: channel)
    try channel.writeInbound(WebSocketFrame(fin: true, opcode: .text, data: payload))
    XCTAssertEqual(box.violations, [.textFrame])
    XCTAssertFalse(channel.isActive)
  }

  func testReservedBitsAreRejectedBecauseCompressionIsNeverNegotiated() throws {
    for index in 0..<3 {
      let (channel, box) = makeChannel()
      defer { _ = try? channel.finish() }
      var frame = WebSocketFrame(fin: true, opcode: .binary, data: buffer(8, in: channel))
      frame.rsv1 = index == 0
      frame.rsv2 = index == 1
      frame.rsv3 = index == 2
      try channel.writeInbound(frame)
      XCTAssertEqual(box.violations, [.reservedBit])
      XCTAssertFalse(channel.isActive)
    }
  }

  func testOversizedSingleMessageIsRejected() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    let payload = buffer(SecureTransportLimits.maxMessageBytes + 1, in: channel)
    try channel.writeInbound(WebSocketFrame(fin: true, opcode: .binary, data: payload))
    XCTAssertEqual(box.violations, [.messageSize])
    XCTAssertFalse(channel.isActive)
  }

  func testFragmentCountCeilingIsEnforced() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: buffer(4, in: channel)))
    for _ in 0..<(SecureTransportLimits.maxFragmentsPerMessage - 1) {
      try channel.writeInbound(
        WebSocketFrame(fin: false, opcode: .continuation, data: buffer(4, in: channel)))
    }
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .continuation, data: buffer(4, in: channel)))
    XCTAssertEqual(box.violations, [.fragmentCount])
    XCTAssertFalse(channel.isActive)
  }

  func testAggregateSizeCeilingAcrossFragmentsIsEnforced() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    let chunk = SecureTransportLimits.maxMessageBytes / 4
    try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: buffer(chunk, in: channel)))
    for _ in 0..<3 {
      try channel.writeInbound(
        WebSocketFrame(fin: false, opcode: .continuation, data: buffer(chunk, in: channel)))
    }
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .continuation, data: buffer(16, in: channel)))
    XCTAssertEqual(box.violations, [.messageSize])
    XCTAssertFalse(channel.isActive)
  }

  func testUnexpectedContinuationIsRejected() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .continuation, data: buffer(4, in: channel)))
    XCTAssertEqual(box.violations, [.unexpectedContinuation])
    XCTAssertFalse(channel.isActive)
  }

  func testNewMessageDuringFragmentationIsRejected() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: buffer(4, in: channel)))
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .binary, data: buffer(4, in: channel)))
    XCTAssertEqual(box.violations, [.newMessageBeforeCompletion])
    XCTAssertFalse(channel.isActive)
  }

  func testEmptyNonFinalFragmentIsRejected() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: channel.allocator.buffer(capacity: 0)))
    XCTAssertEqual(box.violations, [.fragmentTooSmall])
    XCTAssertFalse(channel.isActive)
  }

  func testReservedBitOnAContinuationFrameIsRejected() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: buffer(4, in: channel)))
    var continuation = WebSocketFrame(
      fin: true, opcode: .continuation, data: buffer(4, in: channel))
    continuation.rsv1 = true
    try channel.writeInbound(continuation)
    XCTAssertEqual(box.violations, [.reservedBit])
    XCTAssertFalse(channel.isActive)
  }

  func testControlFrameMayInterleaveWithFragmentation() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: buffer(4, in: channel)))
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .ping, data: channel.allocator.buffer(capacity: 0)))
    let pong = try channel.readOutbound(as: WebSocketFrame.self)
    XCTAssertEqual(pong?.opcode, .pong)
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .continuation, data: buffer(4, in: channel)))
    let assembled = try channel.readInbound(as: ByteBuffer.self)
    XCTAssertEqual(assembled?.readableBytes, 8)
    XCTAssertTrue(box.violations.isEmpty)
    XCTAssertTrue(channel.isActive)
  }

  func testOversizedControlFrameIsRejected() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .ping, data: buffer(126, in: channel)))
    XCTAssertEqual(box.violations, [.oversizedControlFrame])
    XCTAssertFalse(channel.isActive)
  }

  func testCloseFrameClosesTheConnection() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(
        fin: true, opcode: .connectionClose, data: channel.allocator.buffer(capacity: 0)))
    XCTAssertTrue(box.violations.isEmpty)
    XCTAssertFalse(channel.isActive)
  }

  func testOutboundApplicationBytesBecomeSingleBinaryFrames() throws {
    let (channel, _) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeOutbound(buffer(32, in: channel))
    let frame = try channel.readOutbound(as: WebSocketFrame.self)
    XCTAssertEqual(frame?.opcode, .binary)
    XCTAssertTrue(frame?.fin == true)
    XCTAssertEqual(frame?.data.readableBytes, 32)
  }

  func testFragmentedMessageAtTheCeilingIsAccepted() throws {
    let (channel, box) = makeChannel()
    defer { _ = try? channel.finish() }
    try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: buffer(4, in: channel)))
    for _ in 0..<(SecureTransportLimits.maxFragmentsPerMessage - 2) {
      try channel.writeInbound(
        WebSocketFrame(fin: false, opcode: .continuation, data: buffer(4, in: channel)))
    }
    try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .continuation, data: buffer(4, in: channel)))
    let assembled = try channel.readInbound(as: ByteBuffer.self)
    XCTAssertEqual(assembled?.readableBytes, 4 * SecureTransportLimits.maxFragmentsPerMessage)
    XCTAssertTrue(box.violations.isEmpty)
    XCTAssertTrue(channel.isActive)
  }
}
