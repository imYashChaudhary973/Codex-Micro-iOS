import Foundation
import NIOCore
import NIOEmbedded
import NIOHTTP1
import NIOWebSocket
import Testing

@testable import Phase2Transport

struct WebSocketPolicyTests {
  @Test
  func validUpgradeProducesOnlyFixedSubprotocol() throws {
    let result = HardenedWebSocketPolicy().evaluate(validRequest())
    let headers = try result.get()
    #expect(headers["Sec-WebSocket-Protocol"] == [HardenedWebSocketPolicy.subprotocol])
    #expect(headers.count == 1)
  }

  @Test(arguments: [
    WebSocketUpgradeRejection.method,
    .version,
    .pathOrQuery,
    .origin,
    .protocolToken,
    .websocketExtensions,
    .headerName,
  ])
  func rejectsInvalidUpgrade(_ expected: WebSocketUpgradeRejection) {
    var request = validRequest()
    switch expected {
    case .method:
      request.method = .POST
    case .version:
      request.version = .http1_0
    case .pathOrQuery:
      request.uri += "?sentinel=1"
    case .origin:
      request.headers.replaceOrAdd(name: "Origin", value: "https://sentinel.invalid")
    case .protocolToken:
      request.headers.replaceOrAdd(name: "Sec-WebSocket-Protocol", value: "sentinel")
    case .websocketExtensions:
      request.headers.add(name: "Sec-WebSocket-Extensions", value: "sentinel-extension")
    case .headerName:
      request.headers.add(name: "Cookie", value: "sentinel")
    default:
      Issue.record("Unhandled test case")
    }

    #expect(HardenedWebSocketPolicy().evaluate(request) == .failure(expected))
  }

  @Test
  func knownCompressionOfferIsExplicitlyDeclined() throws {
    var request = validRequest()
    request.headers.add(name: "Sec-WebSocket-Extensions", value: "permessage-deflate")
    let response = try HardenedWebSocketPolicy().evaluate(request).get()
    #expect(response[canonicalForm: "Sec-WebSocket-Extensions"].isEmpty)
  }

  @Test
  func rejectsDuplicateRequiredHeaderAndInvalidKey() {
    var duplicate = validRequest()
    duplicate.headers.add(name: "Origin", value: HardenedWebSocketPolicy.origin)
    #expect(HardenedWebSocketPolicy().evaluate(duplicate) == .failure(.origin))

    var invalidKey = validRequest()
    invalidKey.headers.replaceOrAdd(name: "Sec-WebSocket-Key", value: "AAAA")
    #expect(HardenedWebSocketPolicy().evaluate(invalidKey) == .failure(.requiredHeader))
  }

  @Test
  func enforcesHeaderCountAndSize() {
    var tooMany = validRequest()
    for index in 0..<10 {
      tooMany.headers.add(name: "User-Agent", value: "\(index)")
    }
    #expect(HardenedWebSocketPolicy().evaluate(tooMany) == .failure(.headerCount))

    var tooLarge = validRequest()
    tooLarge.headers.add(name: "User-Agent", value: String(repeating: "s", count: 8 * 1024))
    #expect(HardenedWebSocketPolicy().evaluate(tooLarge) == .failure(.headerSize))
  }

  @Test
  func binaryMessagePolicyRejectsTextReservedAndUnaggregatedFragments() throws {
    let handler = BinaryMessagePolicyHandler()
    let allocator = ByteBufferAllocator()
    let data = allocator.buffer(bytes: [1, 2, 3])
    try handler.validate(WebSocketFrame(fin: true, opcode: .binary, data: data))
    #expect(throws: BinaryMessagePolicyError.textFrame) {
      try handler.validate(WebSocketFrame(fin: true, opcode: .text, data: data))
    }
    #expect(throws: BinaryMessagePolicyError.fragmentedFrameEscapedAggregator) {
      try handler.validate(WebSocketFrame(fin: false, opcode: .binary, data: data))
    }
    var reserved = WebSocketFrame(fin: true, opcode: .binary, data: data)
    reserved.rsv1 = true
    #expect(throws: BinaryMessagePolicyError.reservedBit) {
      try handler.validate(reserved)
    }
    let oversized = allocator.buffer(
      repeating: 0,
      count: HardenedWebSocketPolicy.maxMessageBytes + 1
    )
    #expect(throws: BinaryMessagePolicyError.messageTooLarge) {
      try handler.validate(WebSocketFrame(fin: true, opcode: .binary, data: oversized))
    }
  }

  @Test
  func frameAggregatorBoundsFragmentCountAndTotalSize() throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandlers(
      BoundedFragmentAggregator(
        minimumNonFinalFragmentSize: 1,
        maximumFragmentCount: 2,
        maximumMessageSize: 4
      ),
      BinaryMessagePolicyHandler()
    )

    let allocator = ByteBufferAllocator()
    let first = allocator.buffer(bytes: [1, 2])
    let second = allocator.buffer(bytes: [3, 4])
    _ = try channel.writeInbound(WebSocketFrame(fin: false, opcode: .binary, data: first))
    _ = try channel.writeInbound(WebSocketFrame(fin: true, opcode: .continuation, data: second))
    let maybeEchoed: WebSocketFrame? = try channel.readOutbound()
    let echoed = try #require(maybeEchoed)
    #expect(echoed.opcode == .binary)
    #expect(echoed.data.readableBytes == 4)
    let leftovers = try channel.finish()
    #expect(leftovers.isClean)
  }

  @Test
  func fragmentAggregatorRejectsEveryMalformedSequence() throws {
    let allocator = ByteBufferAllocator()
    let one = allocator.buffer(bytes: [1])
    let two = allocator.buffer(bytes: [1, 2])

    try expectAggregatorClose([
      WebSocketFrame(fin: true, opcode: .continuation, data: one)
    ])
    try expectAggregatorClose([
      WebSocketFrame(fin: false, opcode: .binary, data: two),
      WebSocketFrame(fin: true, opcode: .binary, data: two),
    ])
    try expectAggregatorClose(
      [
        WebSocketFrame(fin: false, opcode: .binary, data: one)
      ],
      minimumFragmentSize: 2
    )
    try expectAggregatorClose(
      [
        WebSocketFrame(fin: false, opcode: .binary, data: two),
        WebSocketFrame(fin: false, opcode: .continuation, data: one),
        WebSocketFrame(fin: true, opcode: .continuation, data: one),
      ],
      maximumFragments: 2
    )
    try expectAggregatorClose(
      [
        WebSocketFrame(fin: false, opcode: .binary, data: two),
        WebSocketFrame(fin: true, opcode: .continuation, data: two),
      ],
      maximumMessageSize: 3
    )

    var reservedInitial = WebSocketFrame(fin: false, opcode: .binary, data: one)
    reservedInitial.rsv1 = true
    try expectAggregatorClose([reservedInitial])

    var reservedContinuation = WebSocketFrame(fin: true, opcode: .continuation, data: one)
    reservedContinuation.rsv2 = true
    try expectAggregatorClose([
      WebSocketFrame(fin: false, opcode: .binary, data: one),
      reservedContinuation,
    ])
  }

  @Test
  func controlFramesInterleaveWithoutLosingFragmentState() throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandlers(
      BoundedFragmentAggregator(
        minimumNonFinalFragmentSize: 1,
        maximumFragmentCount: 3,
        maximumMessageSize: 8
      ),
      BinaryMessagePolicyHandler()
    )
    let allocator = ByteBufferAllocator()
    _ = try channel.writeInbound(
      WebSocketFrame(fin: false, opcode: .binary, data: allocator.buffer(bytes: [1, 2]))
    )
    _ = try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .ping, data: allocator.buffer(bytes: [9]))
    )
    let pong: WebSocketFrame? = try channel.readOutbound()
    #expect(pong?.opcode == .pong)
    _ = try channel.writeInbound(
      WebSocketFrame(fin: true, opcode: .continuation, data: allocator.buffer(bytes: [3, 4]))
    )
    let message: WebSocketFrame? = try channel.readOutbound()
    #expect(message?.opcode == .binary)
    #expect(message?.data.readableBytes == 4)
    #expect(try channel.finish().isClean)
  }

  @Test
  func connectionLimiterReleasesExactlyOnce() throws {
    let limiter = ConnectionLimiter(maximum: 1)
    let lease = try #require(limiter.acquire())
    #expect(limiter.activeCount == 1)
    #expect(limiter.acquire() == nil)
    lease.release()
    lease.release()
    #expect(limiter.activeCount == 0)
    #expect(limiter.acquire() != nil)
  }

  private func expectAggregatorClose(
    _ frames: [WebSocketFrame],
    minimumFragmentSize: Int = 1,
    maximumFragments: Int = 2,
    maximumMessageSize: Int = 4
  ) throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
      BoundedFragmentAggregator(
        minimumNonFinalFragmentSize: minimumFragmentSize,
        maximumFragmentCount: maximumFragments,
        maximumMessageSize: maximumMessageSize
      )
    )
    for frame in frames {
      _ = try? channel.writeInbound(frame)
    }
    #expect(!channel.isActive)
    _ = try channel.finish(acceptAlreadyClosed: true)
  }

  private func validRequest() -> HTTPRequestHead {
    var headers = HTTPHeaders()
    headers.add(name: "Host", value: "127.0.0.1")
    headers.add(name: "Connection", value: "Upgrade")
    headers.add(name: "Upgrade", value: "websocket")
    headers.add(name: "Sec-WebSocket-Version", value: "13")
    headers.add(
      name: "Sec-WebSocket-Key", value: Data(repeating: 7, count: 16).base64EncodedString())
    headers.add(name: "Sec-WebSocket-Protocol", value: HardenedWebSocketPolicy.subprotocol)
    headers.add(name: "Origin", value: HardenedWebSocketPolicy.origin)
    return HTTPRequestHead(
      version: .http1_1, method: .GET, uri: HardenedWebSocketPolicy.path, headers: headers)
  }
}
