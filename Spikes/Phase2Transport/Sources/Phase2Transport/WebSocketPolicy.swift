import Foundation
import NIOCore
import NIOHTTP1
import NIOWebSocket

public enum WebSocketUpgradeRejection: Error, Equatable, Sendable {
  case headerCount
  case headerName
  case headerSize
  case host
  case method
  case origin
  case pathOrQuery
  case protocolToken
  case requiredHeader
  case version
  case websocketExtensions
}

public struct HardenedWebSocketPolicy: Sendable {
  public static let path = "/phase2/transport"
  public static let origin = "https://phase2-spike.invalid"
  public static let subprotocol = "codex-micro.phase2.spike.v1"
  public static let maxHeaderCount = 16
  public static let maxHeaderBytes = 8 * 1024
  public static let maxFrameBytes = 16 * 1024
  public static let maxMessageBytes = 64 * 1024
  public static let maxFragments = 8

  private static let allowedHeaderNames: Set<String> = [
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "host",
    "origin",
    "pragma",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "upgrade",
    "user-agent",
  ]

  public init() {}

  public func evaluate(_ request: HTTPRequestHead) -> Result<HTTPHeaders, WebSocketUpgradeRejection>
  {
    guard request.method == .GET else { return .failure(.method) }
    guard request.version == .http1_1 else { return .failure(.version) }
    guard request.uri == Self.path else { return .failure(.pathOrQuery) }
    guard request.headers.count <= Self.maxHeaderCount else { return .failure(.headerCount) }

    var totalHeaderBytes = 0
    for header in request.headers {
      let name = header.name.lowercased()
      guard Self.allowedHeaderNames.contains(name) else { return .failure(.headerName) }
      totalHeaderBytes += name.utf8.count + header.value.utf8.count + 4
      guard totalHeaderBytes <= Self.maxHeaderBytes else { return .failure(.headerSize) }
    }

    guard singleHeader("host", in: request.headers)?.isEmpty == false else {
      return .failure(.host)
    }
    guard singleHeader("upgrade", in: request.headers)?.lowercased() == "websocket" else {
      return .failure(.requiredHeader)
    }
    guard let connection = singleHeader("connection", in: request.headers),
      commaSeparatedTokens(connection).contains("upgrade")
    else {
      return .failure(.requiredHeader)
    }
    guard singleHeader("sec-websocket-version", in: request.headers) == "13" else {
      return .failure(.requiredHeader)
    }
    guard let key = singleHeader("sec-websocket-key", in: request.headers),
      let decodedKey = Data(base64Encoded: key), decodedKey.count == 16
    else {
      return .failure(.requiredHeader)
    }
    let accepts = request.headers["accept"]
    guard accepts.isEmpty || accepts == ["*/*"] else { return .failure(.requiredHeader) }
    let contentLengths = request.headers["content-length"]
    guard contentLengths.isEmpty || contentLengths == ["0"] else {
      return .failure(.requiredHeader)
    }
    guard singleHeader("origin", in: request.headers) == Self.origin else {
      return .failure(.origin)
    }
    guard let requestedProtocol = singleHeader("sec-websocket-protocol", in: request.headers),
      commaSeparatedTokens(requestedProtocol) == [Self.subprotocol]
    else {
      return .failure(.protocolToken)
    }
    let extensionOffers = request.headers[canonicalForm: "Sec-WebSocket-Extensions"]
    guard extensionOffers.isEmpty || extensionOffers == ["permessage-deflate"] else {
      return .failure(.websocketExtensions)
    }

    var response = HTTPHeaders()
    response.add(name: "Sec-WebSocket-Protocol", value: Self.subprotocol)
    return .success(response)
  }

  private func singleHeader(_ name: String, in headers: HTTPHeaders) -> String? {
    let values = headers[name]
    guard values.count == 1 else { return nil }
    return values[0].trimmingCharacters(in: .whitespaces)
  }

  private func commaSeparatedTokens(_ value: String) -> [String] {
    value.split(separator: ",", omittingEmptySubsequences: false).map {
      $0.trimmingCharacters(in: .whitespaces).lowercased()
    }
  }
}

public enum FragmentAggregationError: Error, Equatable, Sendable {
  case fragmentCount
  case fragmentTooSmall
  case messageSize
  case newMessageBeforeCompletion
  case reservedBit
  case unexpectedContinuation
}

public final class BoundedFragmentAggregator: ChannelInboundHandler, @unchecked Sendable {
  public typealias InboundIn = WebSocketFrame
  public typealias InboundOut = WebSocketFrame

  private let minimumNonFinalFragmentSize: Int
  private let maximumFragmentCount: Int
  private let maximumMessageSize: Int
  private var accumulated: ByteBuffer?
  private var fragmentCount = 0
  private var initialOpcode: WebSocketOpcode?

  public init(
    minimumNonFinalFragmentSize: Int,
    maximumFragmentCount: Int,
    maximumMessageSize: Int
  ) {
    precondition(minimumNonFinalFragmentSize > 0)
    precondition(maximumFragmentCount > 0)
    precondition(maximumMessageSize > 0)
    self.minimumNonFinalFragmentSize = minimumNonFinalFragmentSize
    self.maximumFragmentCount = maximumFragmentCount
    self.maximumMessageSize = maximumMessageSize
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    var frame = unwrapInboundIn(data)
    do {
      guard !frame.rsv1, !frame.rsv2, !frame.rsv3 else {
        throw FragmentAggregationError.reservedBit
      }
      switch frame.opcode {
      case .binary, .text:
        guard initialOpcode == nil else {
          throw FragmentAggregationError.newMessageBeforeCompletion
        }
        if frame.fin {
          context.fireChannelRead(wrapInboundOut(frame))
          return
        }
        guard frame.data.readableBytes >= minimumNonFinalFragmentSize else {
          throw FragmentAggregationError.fragmentTooSmall
        }
        guard frame.data.readableBytes <= maximumMessageSize else {
          throw FragmentAggregationError.messageSize
        }
        initialOpcode = frame.opcode
        accumulated = frame.unmaskedData
        fragmentCount = 1
      case .continuation:
        guard let opcode = initialOpcode, var buffer = accumulated else {
          throw FragmentAggregationError.unexpectedContinuation
        }
        fragmentCount += 1
        guard fragmentCount <= maximumFragmentCount else {
          throw FragmentAggregationError.fragmentCount
        }
        if !frame.fin, frame.data.readableBytes < minimumNonFinalFragmentSize {
          throw FragmentAggregationError.fragmentTooSmall
        }
        var fragment = frame.unmaskedData
        guard buffer.readableBytes + fragment.readableBytes <= maximumMessageSize else {
          throw FragmentAggregationError.messageSize
        }
        buffer.writeBuffer(&fragment)
        if frame.fin {
          clear()
          frame = WebSocketFrame(fin: true, opcode: opcode, data: buffer)
          context.fireChannelRead(wrapInboundOut(frame))
        } else {
          accumulated = buffer
        }
      case .ping, .pong, .connectionClose:
        context.fireChannelRead(wrapInboundOut(frame))
      default:
        throw FragmentAggregationError.unexpectedContinuation
      }
    } catch {
      clear()
      context.close(promise: nil)
    }
  }

  private func clear() {
    accumulated = nil
    fragmentCount = 0
    initialOpcode = nil
  }
}

public enum BinaryMessagePolicyError: Error, Equatable, Sendable {
  case fragmentedFrameEscapedAggregator
  case messageTooLarge
  case reservedBit
  case textFrame
  case unsupportedOpcode
}

public final class BinaryMessagePolicyHandler: ChannelInboundHandler, Sendable {
  public typealias InboundIn = WebSocketFrame
  public typealias OutboundOut = WebSocketFrame

  public init() {}

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    do {
      try validate(frame)
      switch frame.opcode {
      case .binary:
        let response = WebSocketFrame(fin: true, opcode: .binary, data: frame.unmaskedData)
        context.writeAndFlush(wrapOutboundOut(response), promise: nil)
      case .ping:
        let response = WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)
        context.writeAndFlush(wrapOutboundOut(response), promise: nil)
      case .pong:
        break
      case .connectionClose:
        context.close(promise: nil)
      case .continuation, .text:
        preconditionFailure("validated frames cannot reach this branch")
      default:
        context.close(promise: nil)
      }
    } catch {
      context.close(promise: nil)
    }
  }

  public func errorCaught(context: ChannelHandlerContext, error: Error) {
    context.close(promise: nil)
  }

  public func validate(_ frame: WebSocketFrame) throws {
    guard !frame.rsv1, !frame.rsv2, !frame.rsv3 else { throw BinaryMessagePolicyError.reservedBit }
    switch frame.opcode {
    case .binary:
      guard frame.fin else { throw BinaryMessagePolicyError.fragmentedFrameEscapedAggregator }
      guard frame.data.readableBytes <= HardenedWebSocketPolicy.maxMessageBytes else {
        throw BinaryMessagePolicyError.messageTooLarge
      }
    case .text:
      throw BinaryMessagePolicyError.textFrame
    case .continuation:
      throw BinaryMessagePolicyError.fragmentedFrameEscapedAggregator
    case .ping, .pong, .connectionClose:
      guard frame.data.readableBytes <= 125 else { throw BinaryMessagePolicyError.messageTooLarge }
    default:
      throw BinaryMessagePolicyError.unsupportedOpcode
    }
  }
}

public final class ConnectionLimiter: @unchecked Sendable {
  private let lock = NSLock()
  private let maximum: Int
  private var active = 0

  public init(maximum: Int) {
    precondition(maximum > 0)
    self.maximum = maximum
  }

  public func acquire() -> ConnectionLease? {
    lock.withLock {
      guard active < maximum else { return nil }
      active += 1
      return ConnectionLease(limiter: self)
    }
  }

  fileprivate func release() {
    lock.withLock {
      precondition(active > 0)
      active -= 1
    }
  }

  public var activeCount: Int {
    lock.withLock { active }
  }
}

public final class ConnectionLease: @unchecked Sendable {
  private let lock = NSLock()
  private weak var limiter: ConnectionLimiter?
  private var released = false

  fileprivate init(limiter: ConnectionLimiter) {
    self.limiter = limiter
  }

  public func release() {
    lock.withLock {
      guard !released else { return }
      released = true
      limiter?.release()
      limiter = nil
    }
  }

  deinit {
    release()
  }
}

public struct WebSocketUpgradeCompleted: Sendable {
  public init() {}
}

public enum HardenedWebSocketPipeline {
  public static func configure(
    channel: Channel,
    policy: HardenedWebSocketPolicy = .init(),
    rejectionObserver: @escaping @Sendable (WebSocketUpgradeRejection) -> Void = { _ in }
  ) -> EventLoopFuture<Void> {
    let upgrader = NIOWebSocketServerUpgrader(
      maxFrameSize: HardenedWebSocketPolicy.maxFrameBytes,
      automaticErrorHandling: true,
      shouldUpgrade: { channel, request in
        switch policy.evaluate(request) {
        case .success(let headers):
          return channel.eventLoop.makeSucceededFuture(headers)
        case .failure(let rejection):
          rejectionObserver(rejection)
          channel.eventLoop.execute {
            channel.close(promise: nil)
          }
          return channel.eventLoop.makeSucceededFuture(nil)
        }
      },
      upgradePipelineHandler: { channel, _ in
        channel.pipeline.addHandler(
          BoundedFragmentAggregator(
            minimumNonFinalFragmentSize: 1,
            maximumFragmentCount: HardenedWebSocketPolicy.maxFragments,
            maximumMessageSize: HardenedWebSocketPolicy.maxMessageBytes
          )
        ).flatMap {
          channel.pipeline.addHandler(BinaryMessagePolicyHandler())
        }
      }
    )
    let configuration: NIOHTTPServerUpgradeSendableConfiguration = (
      upgraders: [upgrader],
      completionHandler: { context in
        context.pipeline.fireUserInboundEventTriggered(WebSocketUpgradeCompleted())
      }
    )
    var limits = NIOHTTPDecoderLimitConfiguration()
    limits.maxHeaderFieldSize = 4 * 1024
    limits.maxHeaderListSize = HardenedWebSocketPolicy.maxHeaderBytes
    limits.maxHeaderFieldCount = HardenedWebSocketPolicy.maxHeaderCount
    return channel.pipeline.configureHTTPServerPipeline(
      withPipeliningAssistance: false,
      withServerUpgrade: configuration,
      withErrorHandling: true,
      withOutboundHeaderValidation: true,
      withDecoderLimitConfiguration: limits
    )
  }
}
