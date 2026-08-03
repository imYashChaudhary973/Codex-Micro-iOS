import CompanionCrypto
import CompanionProtocol
import Foundation
import NIOCore
import NIOWebSocket

/// Closes a connection that has not completed TLS and the HTTP upgrade
/// inside the deadline (ADR §9: 10 s from accept).
///
/// The timer starts when the handler joins the pipeline, which for a NIOTS
/// child channel is immediately after the connection is accepted, and is
/// cancelled by ``ListenerUpgradeCompleted``. Timing runs on the channel's
/// event loop, so an `EmbeddedEventLoop` drives it deterministically.
public final class ListenerUpgradeDeadlineHandler: ChannelInboundHandler,
  RemovableChannelHandler, @unchecked Sendable
{
  public typealias InboundIn = NIOAny

  private let deadline: TimeAmount
  private let onElapsed: @Sendable () -> Void
  private var scheduled: Scheduled<Void>?

  /// Creates the handler.
  ///
  /// - Parameters:
  ///   - deadline: Time allowed for TLS plus the HTTP upgrade.
  ///   - onElapsed: Closed-code observer invoked when the deadline expires.
  public init(deadline: TimeAmount, onElapsed: @escaping @Sendable () -> Void = {}) {
    self.deadline = deadline
    self.onElapsed = onElapsed
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    let channel = context.channel
    let onElapsed = self.onElapsed
    scheduled = context.eventLoop.scheduleTask(in: deadline) {
      onElapsed()
      channel.close(promise: nil)
    }
  }

  public func handlerRemoved(context: ChannelHandlerContext) {
    cancel()
  }

  public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    guard event is ListenerUpgradeCompleted else {
      context.fireUserInboundEventTriggered(event)
      return
    }
    cancel()
    // The event must be forwarded **before** the handler is removed:
    // `removeHandler` completes synchronously and unlinks this context, so a
    // fire afterwards reaches nobody and every downstream consumer — the
    // authentication deadline in particular — would silently never start.
    context.fireUserInboundEventTriggered(event)
    context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
  }

  public func channelInactive(context: ChannelHandlerContext) {
    cancel()
    context.fireChannelInactive()
  }

  private func cancel() {
    scheduled?.cancel()
    scheduled = nil
  }
}

/// Bounds the raw bytes a peer may send before the HTTP upgrade completes.
///
/// NIO consults the upgrade policy only when an `Upgrade` header is present,
/// so a plain `GET` or `POST` never reaches ``ListenerUpgradePolicy`` and the
/// per-connection meters — which live in the post-upgrade pipeline — never
/// see it. Without this handler a peer could stream a body for the whole
/// TLS+upgrade deadline on every unauthenticated slot. Nothing is disclosed
/// either way; this is a bandwidth and CPU bound.
///
/// It sits ahead of the HTTP decoder so it counts bytes as they arrive, and
/// removes itself once the upgrade completes.
public final class ListenerPreUpgradeByteLimitHandler: ChannelInboundHandler,
  RemovableChannelHandler, @unchecked Sendable
{
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  private let maximumBytes: Int
  private let onExceeded: @Sendable () -> Void
  private var received = 0

  /// Creates the handler.
  public init(maximumBytes: Int, onExceeded: @escaping @Sendable () -> Void = {}) {
    precondition(maximumBytes > 0)
    self.maximumBytes = maximumBytes
    self.onExceeded = onExceeded
  }

  /// The bytes counted so far, for deterministic assertions.
  public var receivedBytes: Int { received }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    received += unwrapInboundIn(data).readableBytes
    guard received <= maximumBytes else {
      onExceeded()
      context.close(promise: nil)
      return
    }
    context.fireChannelRead(data)
  }

  public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    guard event is ListenerUpgradeCompleted else {
      context.fireUserInboundEventTriggered(event)
      return
    }
    context.fireUserInboundEventTriggered(event)
    context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
  }
}

/// Server ping cadence, matching-pong deadline, and post-upgrade application
/// idle expiry (ADR §9: 30 s cadence, 10 s pong deadline, 120 s idle).
///
/// **Where it sits and why.** It is head-ward of
/// ``ListenerBinaryFramePolicy``, so it observes pongs before that handler
/// consumes control frames, and it emits its pings with
/// `context.writeAndFlush` — from its own position toward the head — so the
/// frame reaches the WebSocket encoder through ``ListenerOutboundBoundHandler``
/// and never re-enters a tail-ward handler that expects application bytes.
/// Writing through the channel instead would start at the pipeline tail and
/// hand a `WebSocketFrame` to a handler whose outbound type is `ByteBuffer`,
/// which is an unconditional runtime trap.
///
/// **Cadence starts at authentication.** An unauthenticated connection is
/// already bounded by the much stricter authentication deadline, so no
/// server-originated traffic is needed — or emitted — before
/// ``ListenerConnectionAuthenticated``. ``ListenerCeilings/validated()``
/// additionally refuses a cadence tightened to inside the authentication
/// deadline.
///
/// **The pong must match.** Every ping carries a fresh 8-byte counter
/// payload and only a pong echoing exactly those bytes clears the deadline,
/// so an unsolicited or stale pong cannot keep a dead peer alive.
///
/// Control traffic never resets the idle timer: only a valid inbound
/// **binary** application frame does. Text frames are a policy violation and
/// are rejected downstream, so they must not count as liveness either.
public final class ListenerKeepAliveHandler: ChannelInboundHandler, @unchecked Sendable {
  public typealias InboundIn = WebSocketFrame
  public typealias InboundOut = WebSocketFrame

  private let pingCadence: TimeAmount
  private let pongDeadline: TimeAmount
  private let idleExpiry: TimeAmount
  private let onPongDeadline: @Sendable () -> Void
  private let onIdleExpiry: @Sendable () -> Void
  private var pingTask: RepeatedTask?
  private var pongTask: Scheduled<Void>?
  private var idleTask: Scheduled<Void>?
  private var idleStarted = false
  private var cadenceStarted = false
  private var pingCounter: UInt64 = 0
  private var outstandingPingPayload: Data?
  /// Retained so the repeated ping task can write from **this handler's**
  /// position. It is only ever touched on the channel's event loop, which is
  /// where every scheduled task and every pipeline callback runs.
  private var handlerContext: ChannelHandlerContext?

  /// Creates the handler.
  public init(
    pingCadence: TimeAmount,
    pongDeadline: TimeAmount,
    idleExpiry: TimeAmount,
    onPongDeadline: @escaping @Sendable () -> Void = {},
    onIdleExpiry: @escaping @Sendable () -> Void = {}
  ) {
    self.pingCadence = pingCadence
    self.pongDeadline = pongDeadline
    self.idleExpiry = idleExpiry
    self.onPongDeadline = onPongDeadline
    self.onIdleExpiry = onIdleExpiry
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    handlerContext = context
    guard context.channel.isActive else { return }
    startIdleExpiry(context: context)
  }

  public func channelActive(context: ChannelHandlerContext) {
    handlerContext = context
    startIdleExpiry(context: context)
    context.fireChannelActive()
  }

  public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if event is ListenerConnectionAuthenticated {
      startPingCadence(context: context)
    }
    context.fireUserInboundEventTriggered(event)
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    switch frame.opcode {
    case .pong:
      clearMatchingPong(frame)
    case .binary:
      restartIdleTimer(context: context)
    default:
      break
    }
    context.fireChannelRead(data)
  }

  public func channelInactive(context: ChannelHandlerContext) {
    stop()
    context.fireChannelInactive()
  }

  public func handlerRemoved(context: ChannelHandlerContext) {
    stop()
    handlerContext = nil
  }

  private func startIdleExpiry(context: ChannelHandlerContext) {
    guard !idleStarted else { return }
    idleStarted = true
    restartIdleTimer(context: context)
  }

  private func startPingCadence(context: ChannelHandlerContext) {
    guard !cadenceStarted else { return }
    cadenceStarted = true
    let pongDeadline = self.pongDeadline
    let onPongDeadline = self.onPongDeadline
    pingTask = context.eventLoop.scheduleRepeatedTask(
      initialDelay: pingCadence,
      delay: pingCadence
    ) { [weak self] _ in
      guard let self, let context = self.handlerContext else { return }
      let payload = self.nextPingPayload()
      var buffer = context.channel.allocator.buffer(capacity: payload.count)
      buffer.writeBytes(payload)
      // Head-ward from this handler's own position. Writing through the
      // channel instead would start at the tail and hand a `WebSocketFrame`
      // to a handler whose outbound type is `ByteBuffer`, trapping the
      // process.
      context.writeAndFlush(
        NIOAny(WebSocketFrame(fin: true, opcode: .ping, data: buffer)),
        promise: nil
      )
      let channel = context.channel
      self.pongTask?.cancel()
      self.pongTask = context.eventLoop.scheduleTask(in: pongDeadline) {
        onPongDeadline()
        channel.close(promise: nil)
      }
    }
  }

  private func nextPingPayload() -> Data {
    pingCounter &+= 1
    var payload = Data(count: 8)
    var value = pingCounter.bigEndian
    withUnsafeBytes(of: &value) { bytes in
      payload.replaceSubrange(0..<8, with: bytes)
    }
    outstandingPingPayload = payload
    return payload
  }

  private func clearMatchingPong(_ frame: WebSocketFrame) {
    guard let expected = outstandingPingPayload else { return }
    var data = frame.unmaskedData
    let received = data.readData(length: data.readableBytes) ?? Data()
    guard received == expected else { return }
    outstandingPingPayload = nil
    pongTask?.cancel()
    pongTask = nil
  }

  private func restartIdleTimer(context: ChannelHandlerContext) {
    idleTask?.cancel()
    let channel = context.channel
    let onIdleExpiry = self.onIdleExpiry
    idleTask = context.eventLoop.scheduleTask(in: idleExpiry) {
      onIdleExpiry()
      channel.close(promise: nil)
    }
  }

  private func stop() {
    pingTask?.cancel()
    pingTask = nil
    pongTask?.cancel()
    pongTask = nil
    idleTask?.cancel()
    idleTask = nil
  }
}

/// Per-connection inbound message and byte rate enforcement (ADR §9: 32
/// messages per second, 1 MiB per second). Exceeding either closes the
/// connection.
///
/// It meters **`WebSocketFrame`s immediately after reassembly**, so a
/// reassembled application message counts once while every peer-driven
/// control frame — ping, pong, close — counts too. Metering application
/// bytes further tail-ward would leave control frames free, which is a
/// cheap unauthenticated CPU and bandwidth channel: each inbound ping
/// obliges the server to emit a pong.
public final class ListenerInboundRateHandler: ChannelInboundHandler, @unchecked Sendable {
  public typealias InboundIn = WebSocketFrame
  public typealias InboundOut = WebSocketFrame

  private let meter: ListenerInboundRateMeter
  private let onExceeded: @Sendable () -> Void

  /// Creates the handler around a meter driven by the injected clock.
  public init(meter: ListenerInboundRateMeter, onExceeded: @escaping @Sendable () -> Void = {}) {
    self.meter = meter
    self.onExceeded = onExceeded
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    guard meter.admit(bytes: frame.data.readableBytes) else {
      onExceeded()
      context.close(promise: nil)
      return
    }
    context.fireChannelRead(data)
  }
}

/// Bounded outbound queue and slow-consumer policy (ADR §9: 64 frames or
/// 256 KiB, and close after 10 s non-writable).
///
/// It is the **head-most** handler of the post-upgrade chain and counts
/// `WebSocketFrame`s, so every outbound frame passes through it whatever its
/// origin: application payloads written from the tail, the pongs the frame
/// policy emits in reply to peer pings, and the server's own keep-alive
/// pings. Counting from a tail-ward position would structurally miss the
/// control frames, which is exactly how a peer could drive unbounded
/// outbound work.
///
/// Frames are counted as they are written and discounted when the write
/// completes. Exceeding either bound refuses the write with
/// ``ListenerError/outboundQueueExceeded`` and closes the connection;
/// staying non-writable past the ceiling closes it too.
public final class ListenerOutboundBoundHandler: ChannelDuplexHandler, @unchecked Sendable {
  public typealias InboundIn = WebSocketFrame
  public typealias InboundOut = WebSocketFrame
  public typealias OutboundIn = WebSocketFrame
  public typealias OutboundOut = WebSocketFrame

  private let maxFrames: Int
  private let maxBytes: Int
  private let nonWritableLimit: TimeAmount
  private let onQueueExceeded: @Sendable () -> Void
  private let onSlowConsumer: @Sendable () -> Void
  private var pendingFrames = 0
  private var pendingBytes = 0
  private var nonWritableTask: Scheduled<Void>?

  /// Creates the handler.
  public init(
    maxFrames: Int,
    maxBytes: Int,
    nonWritableLimit: TimeAmount,
    onQueueExceeded: @escaping @Sendable () -> Void = {},
    onSlowConsumer: @escaping @Sendable () -> Void = {}
  ) {
    precondition(maxFrames > 0)
    precondition(maxBytes > 0)
    self.maxFrames = maxFrames
    self.maxBytes = maxBytes
    self.nonWritableLimit = nonWritableLimit
    self.onQueueExceeded = onQueueExceeded
    self.onSlowConsumer = onSlowConsumer
  }

  /// The current queue depth, for deterministic assertions.
  public var pending: (frames: Int, bytes: Int) {
    (pendingFrames, pendingBytes)
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    let frame = unwrapOutboundIn(data)
    let bytes = frame.data.readableBytes
    guard pendingFrames + 1 <= maxFrames, pendingBytes + bytes <= maxBytes else {
      onQueueExceeded()
      promise?.fail(ListenerError.outboundQueueExceeded)
      context.close(promise: nil)
      return
    }
    pendingFrames += 1
    pendingBytes += bytes
    let completion = context.eventLoop.makePromise(of: Void.self)
    completion.futureResult.whenComplete { [weak self] _ in
      guard let self else { return }
      self.pendingFrames = max(0, self.pendingFrames - 1)
      self.pendingBytes = max(0, self.pendingBytes - bytes)
    }
    if let promise {
      completion.futureResult.cascade(to: promise)
    }
    context.write(data, promise: completion)
  }

  public func channelWritabilityChanged(context: ChannelHandlerContext) {
    if context.channel.isWritable {
      nonWritableTask?.cancel()
      nonWritableTask = nil
    } else if nonWritableTask == nil {
      let channel = context.channel
      let onSlowConsumer = self.onSlowConsumer
      nonWritableTask = context.eventLoop.scheduleTask(in: nonWritableLimit) {
        onSlowConsumer()
        channel.close(promise: nil)
      }
    }
    context.fireChannelWritabilityChanged()
  }

  public func channelInactive(context: ChannelHandlerContext) {
    nonWritableTask?.cancel()
    nonWritableTask = nil
    context.fireChannelInactive()
  }

  public func handlerRemoved(context: ChannelHandlerContext) {
    nonWritableTask?.cancel()
    nonWritableTask = nil
  }
}

/// The pre-authentication gate (plan §7 gate 2, ADR §9 authentication
/// deadline).
///
/// Until the connection authenticates it may carry only the four
/// device-originated handshake kinds, one at a time, inside the
/// authentication deadline, and inside that kind's per-source ceiling.
///
/// **Every pre-authentication refusal writes the same closed reason.** The
/// gate collapses its own refusals *and* whatever reason the handshake seam
/// returns onto ``ListenerPreAuthAllowlist/collapsedRefusal``, so a
/// malformed body, an application message, an exhausted shared per-source
/// counter, a failed pairing, and a failed authentication are one
/// indistinguishable outcome. Specific reasons pass through unchanged only
/// after the peer has authenticated. No thread, project, Codex, grant, or
/// journal value can reach this path at all — the transport holds none of
/// it.
public final class ListenerHandshakeGateHandler: ChannelInboundHandler, @unchecked Sendable {
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  private let connectionID: UUID
  private let source: ListenerSourceKey
  private let admission: ListenerAdmissionController
  private let ticket: ListenerConnectionTicket
  private let handshake: any ListenerHandshakeHandling
  private let allowlist = ListenerPreAuthAllowlist()
  private let authenticationDeadline: TimeAmount
  private let logger: any ListenerLogging
  private var deadlineTask: Scheduled<Void>?
  private var authenticated = false
  private var dispatchInFlight = false

  /// Creates the gate.
  public init(
    connectionID: UUID,
    source: ListenerSourceKey,
    admission: ListenerAdmissionController,
    ticket: ListenerConnectionTicket,
    handshake: any ListenerHandshakeHandling,
    authenticationDeadline: TimeAmount,
    logger: any ListenerLogging
  ) {
    self.connectionID = connectionID
    self.source = source
    self.admission = admission
    self.ticket = ticket
    self.handshake = handshake
    self.authenticationDeadline = authenticationDeadline
    self.logger = logger
  }

  /// Whether this connection completed authentication.
  public var isAuthenticated: Bool { authenticated }

  public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if event is ListenerUpgradeCompleted {
      startAuthenticationDeadline(context: context)
    }
    if event is ListenerConnectionAuthenticated {
      authenticated = true
      deadlineTask?.cancel()
      deadlineTask = nil
    }
    context.fireUserInboundEventTriggered(event)
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    guard context.channel.isActive else { return }
    startAuthenticationDeadline(context: context)
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    guard !authenticated else {
      context.fireChannelRead(data)
      return
    }
    let payload = unwrapInboundIn(data)
    guard !dispatchInFlight else {
      logger.record(.preAuthMessageRejected)
      refuse(context: context, reason: ListenerPreAuthAllowlist.collapsedRefusal)
      return
    }
    var buffer = payload
    let bytes = buffer.readData(length: buffer.readableBytes) ?? Data()
    switch allowlist.classify(bytes) {
    case .refused(let reason):
      logger.record(.preAuthMessageRejected)
      refuse(context: context, reason: reason)
    case .allowed(let envelope):
      guard admission.admitHandshakeMessage(envelope.kind, source: source) else {
        // The reason stays collapsed: this counter is shared by every peer
        // behind one source address, so a distinct rate-limited reason would
        // disclose another device's recent activity.
        logger.record(.handshakeRateExceeded)
        refuse(context: context, reason: ListenerPreAuthAllowlist.collapsedRefusal)
        return
      }
      dispatch(envelope, context: context)
    }
  }

  public func channelInactive(context: ChannelHandlerContext) {
    deadlineTask?.cancel()
    deadlineTask = nil
    let handshake = self.handshake
    let connectionID = self.connectionID
    Task { await handshake.abandon(connectionID: connectionID) }
    context.fireChannelInactive()
  }

  private func startAuthenticationDeadline(context: ChannelHandlerContext) {
    guard deadlineTask == nil, !authenticated else { return }
    let channel = context.channel
    let logger = self.logger
    deadlineTask = context.eventLoop.scheduleTask(in: authenticationDeadline) {
      logger.record(.authenticationDeadlineElapsed)
      channel.close(promise: nil)
    }
  }

  private func dispatch(_ envelope: ListenerHandshakeEnvelope, context: ChannelHandlerContext) {
    dispatchInFlight = true
    let channel = context.channel
    let eventLoop = context.eventLoop
    let handshake = self.handshake
    let connectionID = self.connectionID
    Task { [weak self] in
      let outcome = await handshake.handle(envelope, connectionID: connectionID)
      guard let gate = self else { return }
      eventLoop.execute {
        gate.apply(outcome, channel: channel)
      }
    }
  }

  private func apply(_ outcome: ListenerHandshakeOutcome, channel: Channel) {
    dispatchInFlight = false
    switch outcome {
    case .reply(let envelope):
      _ = write(envelope, to: channel)
    case .authenticated(let reply, _):
      authenticated = true
      deadlineTask?.cancel()
      deadlineTask = nil
      ticket.markAuthenticated()
      logger.record(.connectionAuthenticated)
      if let reply {
        _ = write(reply, to: channel)
      }
      channel.pipeline.fireUserInboundEventTriggered(ListenerConnectionAuthenticated())
    case .close(let reason):
      // Collapse whatever the seam decided: before authentication the peer
      // learns only that it was refused.
      closeAfterNotice(collapsed(reason), channel: channel)
    }
  }

  private func refuse(context: ChannelHandlerContext, reason: SecureCloseReason) {
    closeAfterNotice(collapsed(reason), channel: context.channel)
  }

  /// Maps any reason onto the single pre-authentication reason while the
  /// connection is unauthenticated; post-authentication reasons pass through.
  private func collapsed(_ reason: SecureCloseReason) -> SecureCloseReason {
    authenticated ? reason : ListenerPreAuthAllowlist.collapsedRefusal
  }

  /// Writes the single closed reason and closes only once it is flushed, so
  /// the peer always receives the reason rather than a bare disconnect.
  private func closeAfterNotice(_ reason: SecureCloseReason, channel: Channel) {
    guard let body = try? JSONEncoder().encode(SecureCloseNotice(reason: reason)),
      let envelope = try? ListenerHandshakeEnvelope(kind: .closeNotice, payload: body)
    else {
      channel.close(promise: nil)
      return
    }
    write(envelope, to: channel).whenComplete { _ in
      channel.close(promise: nil)
    }
  }

  private func write(
    _ envelope: ListenerHandshakeEnvelope,
    to channel: Channel
  ) -> EventLoopFuture<Void> {
    guard let encoded = try? envelope.encoded() else {
      channel.close(promise: nil)
      return channel.eventLoop.makeSucceededVoidFuture()
    }
    var buffer = channel.allocator.buffer(capacity: encoded.count)
    buffer.writeBytes(encoded)
    return channel.writeAndFlush(buffer)
  }
}
