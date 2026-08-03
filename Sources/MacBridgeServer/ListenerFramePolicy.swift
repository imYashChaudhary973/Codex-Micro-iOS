import CompanionProtocol
import Foundation
import NIOCore
import NIOWebSocket

/// Closed WebSocket frame-policy violation vocabulary (ADR §9).
///
/// Every violation closes the connection. The code never travels to the
/// peer and carries no frame bytes.
public enum ListenerFrameViolation: String, Error, Equatable, CaseIterable, Sendable {
  /// More fragments than the ceiling allows.
  case fragmentCount
  /// A non-final fragment carried no payload.
  case fragmentTooSmall
  /// A complete message exceeded the message ceiling.
  case messageSize
  /// A new data frame arrived while a fragmented message was open.
  case newMessageBeforeCompletion
  /// A reserved bit was set: compression is never negotiated, so RSV1 in
  /// particular is always a violation.
  case reservedBit
  /// A continuation frame arrived with no message open.
  case unexpectedContinuation
  /// A text frame arrived; only binary application frames are accepted.
  case textFrame
  /// An opcode outside the accepted set arrived.
  case unsupportedOpcode
  /// A control frame exceeded the 125-byte protocol limit.
  case oversizedControlFrame
  /// A fragmented frame reached the policy handler, which only ever sees
  /// reassembled messages.
  case fragmentEscapedAggregator
}

/// Reassembles fragmented WebSocket messages under the ADR §9 ceilings and
/// closes the connection on any violation.
///
/// Control frames pass through untouched so a ping can interleave with a
/// fragmented message, which RFC 6455 requires.
public final class ListenerFragmentAggregator: ChannelInboundHandler, @unchecked Sendable {
  public typealias InboundIn = WebSocketFrame
  public typealias InboundOut = WebSocketFrame

  private let maximumFragmentCount: Int
  private let maximumMessageBytes: Int
  private let onViolation: @Sendable (ListenerFrameViolation) -> Void
  private var accumulated: ByteBuffer?
  private var fragmentCount = 0
  private var initialOpcode: WebSocketOpcode?

  /// Creates an aggregator bound to the ADR ceilings.
  ///
  /// - Parameters:
  ///   - maximumFragmentCount: Fragments per message (ADR §9: 8).
  ///   - maximumMessageBytes: Reassembled message ceiling (ADR §9: 64 KiB).
  ///   - onViolation: Observer for the closed violation code. It receives
  ///     only the enum; nothing peer-derived is passed.
  public init(
    maximumFragmentCount: Int = SecureTransportLimits.maxFragmentsPerMessage,
    maximumMessageBytes: Int = SecureTransportLimits.maxMessageBytes,
    onViolation: @escaping @Sendable (ListenerFrameViolation) -> Void = { _ in }
  ) {
    precondition(maximumFragmentCount > 0)
    precondition(maximumMessageBytes > 0)
    self.maximumFragmentCount = maximumFragmentCount
    self.maximumMessageBytes = maximumMessageBytes
    self.onViolation = onViolation
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    var frame = unwrapInboundIn(data)
    do {
      guard !frame.rsv1, !frame.rsv2, !frame.rsv3 else {
        throw ListenerFrameViolation.reservedBit
      }
      switch frame.opcode {
      case .binary, .text:
        guard initialOpcode == nil else {
          throw ListenerFrameViolation.newMessageBeforeCompletion
        }
        if frame.fin {
          context.fireChannelRead(wrapInboundOut(frame))
          return
        }
        guard frame.data.readableBytes > 0 else {
          throw ListenerFrameViolation.fragmentTooSmall
        }
        guard frame.data.readableBytes <= maximumMessageBytes else {
          throw ListenerFrameViolation.messageSize
        }
        initialOpcode = frame.opcode
        accumulated = frame.unmaskedData
        fragmentCount = 1
      case .continuation:
        guard let opcode = initialOpcode, var buffer = accumulated else {
          throw ListenerFrameViolation.unexpectedContinuation
        }
        fragmentCount += 1
        guard fragmentCount <= maximumFragmentCount else {
          throw ListenerFrameViolation.fragmentCount
        }
        if !frame.fin, frame.data.readableBytes == 0 {
          throw ListenerFrameViolation.fragmentTooSmall
        }
        var fragment = frame.unmaskedData
        guard buffer.readableBytes + fragment.readableBytes <= maximumMessageBytes else {
          throw ListenerFrameViolation.messageSize
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
        throw ListenerFrameViolation.unsupportedOpcode
      }
    } catch let violation as ListenerFrameViolation {
      clear()
      onViolation(violation)
      context.close(promise: nil)
    } catch {
      clear()
      context.close(promise: nil)
    }
  }

  public func channelInactive(context: ChannelHandlerContext) {
    clear()
    context.fireChannelInactive()
  }

  private func clear() {
    accumulated = nil
    fragmentCount = 0
    initialOpcode = nil
  }
}

/// Enforces the binary-only application-frame policy on reassembled
/// messages, answers pings, and forwards application payloads inward.
///
/// Text frames, reserved bits, oversized messages, oversized control
/// frames, and unknown opcodes all close the connection. Nothing is echoed:
/// the payload travels inward to the handshake gate, which decides what — if
/// anything — the peer may receive.
public final class ListenerBinaryFramePolicy: ChannelDuplexHandler, @unchecked Sendable {
  public typealias InboundIn = WebSocketFrame
  public typealias InboundOut = ByteBuffer
  public typealias OutboundIn = ByteBuffer
  public typealias OutboundOut = WebSocketFrame

  private let maximumMessageBytes: Int
  private let onViolation: @Sendable (ListenerFrameViolation) -> Void

  /// Creates the policy handler bound to the ADR §9 message ceiling.
  public init(
    maximumMessageBytes: Int = SecureTransportLimits.maxMessageBytes,
    onViolation: @escaping @Sendable (ListenerFrameViolation) -> Void = { _ in }
  ) {
    self.maximumMessageBytes = maximumMessageBytes
    self.onViolation = onViolation
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    do {
      try validate(frame)
      switch frame.opcode {
      case .binary:
        context.fireChannelRead(wrapInboundOut(frame.unmaskedData))
      case .ping:
        // The reply travels head-ward from this position, so it passes
        // through the outbound queue accounting exactly like an application
        // frame. The inbound ping was already metered by the rate handler,
        // which sits head-ward of this one.
        let pong = WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)
        context.writeAndFlush(NIOAny(pong), promise: nil)
      case .pong:
        // The keep-alive handler is head-ward of this one and has already
        // matched the payload against its outstanding ping.
        break
      case .connectionClose:
        context.close(promise: nil)
      case .continuation, .text:
        throw ListenerFrameViolation.fragmentEscapedAggregator
      default:
        throw ListenerFrameViolation.unsupportedOpcode
      }
    } catch let violation as ListenerFrameViolation {
      onViolation(violation)
      context.close(promise: nil)
    } catch {
      context.close(promise: nil)
    }
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    let payload = unwrapOutboundIn(data)
    let frame = WebSocketFrame(fin: true, opcode: .binary, data: payload)
    context.write(wrapOutboundOut(frame), promise: promise)
  }

  public func errorCaught(context: ChannelHandlerContext, error: Error) {
    context.close(promise: nil)
  }

  /// Validates one reassembled frame against the ADR §9 policy.
  public func validate(_ frame: WebSocketFrame) throws {
    guard !frame.rsv1, !frame.rsv2, !frame.rsv3 else {
      throw ListenerFrameViolation.reservedBit
    }
    switch frame.opcode {
    case .binary:
      guard frame.fin else { throw ListenerFrameViolation.fragmentEscapedAggregator }
      guard frame.data.readableBytes <= maximumMessageBytes else {
        throw ListenerFrameViolation.messageSize
      }
    case .text:
      throw ListenerFrameViolation.textFrame
    case .continuation:
      throw ListenerFrameViolation.fragmentEscapedAggregator
    case .ping, .pong, .connectionClose:
      guard frame.data.readableBytes <= 125 else {
        throw ListenerFrameViolation.oversizedControlFrame
      }
    default:
      throw ListenerFrameViolation.unsupportedOpcode
    }
  }
}

/// Pipeline event announcing that the HTTP upgrade completed. It stops the
/// TLS+upgrade deadline and starts the authentication deadline.
public struct ListenerUpgradeCompleted: Sendable {
  /// Creates the event.
  public init() {}
}

/// Pipeline event announcing that the connection authenticated. It stops the
/// authentication deadline and lifts the pre-authentication allowlist.
public struct ListenerConnectionAuthenticated: Sendable {
  /// Creates the event.
  public init() {}
}
