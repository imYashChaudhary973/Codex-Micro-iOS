import CompanionCrypto
import CompanionProtocol
import Foundation
import NIOCore

/// The tail handler of an authenticated connection: it opens every inbound
/// sealed frame, enforces the post-authentication allowlist, and seals every
/// outbound delivery.
///
/// **Every post-handshake payload is independently sealed** (plan §2
/// invariant 9). The frame codecs come from the session handshake, not from
/// TLS, and their per-direction counters are exactly-next, so a duplicate,
/// gap, reflected, cross-connection, or tampered frame closes the connection
/// (invariant 10) — this handler adds no tolerance of its own on top of the
/// Step 2.3 codec.
///
/// **Ownership of the codecs transfers once.** The counters must never be
/// advanced from two places, so the handler takes the codecs from the
/// provider and the provider forgets them. Inbound frames that arrive before
/// the transfer completes are held, at most one, and a second one closes the
/// connection rather than growing a queue.
///
/// **Nothing is disclosed that the seam did not already filter.** The
/// transport never sees an unfiltered journal and never decides what a device
/// may observe.
public final class ListenerObservationHandler: ChannelInboundHandler, @unchecked Sendable {
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  private let connectionID: UUID
  private let observation: any ListenerObservationHandling
  private let commands: any ListenerCommandHandling
  private let frameProvider: any ListenerSessionFrameProviding
  private let logger: any ListenerLogging
  private var frames: ListenerSessionFrames?
  private var authenticated = false
  private var awaitingFrames = false
  private var pendingInbound: Data?
  private var dispatchInFlight = false
  private var released = false
  /// Set when this build carries no post-authentication traffic, so the
  /// connection stays alive but inert.
  private var framesUnavailable = false
  /// The subscription the device last opened. Deliveries echo it, so a batch
  /// can never be attributed to a subscription the device is not waiting on.
  private var activeSubscriptionID: UUID?

  /// Creates the handler.
  public init(
    connectionID: UUID,
    observation: any ListenerObservationHandling,
    commands: any ListenerCommandHandling = DenyingListenerCommandHandler(),
    frameProvider: any ListenerSessionFrameProviding,
    logger: any ListenerLogging
  ) {
    self.connectionID = connectionID
    self.observation = observation
    self.commands = commands
    self.frameProvider = frameProvider
    self.logger = logger
  }

  /// Whether the connection has taken ownership of its frame codecs.
  public var hasSessionFrames: Bool { frames != nil }

  public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if event is ListenerConnectionAuthenticated, !authenticated {
      authenticated = true
      requestFrames(context: context)
    }
    context.fireUserInboundEventTriggered(event)
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    guard authenticated else {
      // Pre-authentication traffic never reaches here: the gate consumes it.
      context.fireChannelRead(data)
      return
    }
    var buffer = unwrapInboundIn(data)
    let bytes = buffer.readData(length: buffer.readableBytes) ?? Data()

    guard frames != nil else {
      // Inert or still claiming codecs: hold at most one message, and close
      // on anything the connection can never open.
      guard awaitingFrames, !framesUnavailable, pendingInbound == nil else {
        close(context.channel, reason: .protocolViolation)
        return
      }
      pendingInbound = bytes
      return
    }
    guard !dispatchInFlight else {
      close(context.channel, reason: .rateLimited)
      return
    }
    consume(bytes, channel: context.channel)
  }

  public func channelInactive(context: ChannelHandlerContext) {
    releaseState()
    context.fireChannelInactive()
  }

  // MARK: - Frame ownership

  private func requestFrames(context: ChannelHandlerContext) {
    awaitingFrames = true
    let channel = context.channel
    let eventLoop = context.eventLoop
    let provider = frameProvider
    let connectionID = self.connectionID
    Task { [weak self] in
      let taken = await provider.takeFrames(connectionID: connectionID)
      guard let handler = self else { return }
      eventLoop.execute {
        handler.install(taken, channel: channel)
      }
    }
  }

  private func install(_ taken: ListenerSessionFrames?, channel: Channel) {
    awaitingFrames = false
    guard let taken else {
      // No codecs means this build carries no post-authentication traffic —
      // the Step 2.7 behaviour, where an authenticated connection is admitted,
      // counted, and kept alive while nothing is delivered. The connection is
      // left alive but inert: it cannot open a single sealed byte, so any
      // application message it sends closes it below.
      framesUnavailable = true
      if pendingInbound != nil {
        pendingInbound = nil
        close(channel, reason: .protocolViolation)
      }
      return
    }
    frames = taken
    if let pending = pendingInbound {
      pendingInbound = nil
      consume(pending, channel: channel)
    }
  }

  // MARK: - Inbound

  private func consume(_ bytes: Data, channel: Channel) {
    guard var current = frames else {
      close(channel, reason: .authenticationFailed)
      return
    }
    let plaintext: Data
    do {
      plaintext = try current.inbound.open(bytes)
      frames = current
    } catch {
      // The Step 2.3 opener has already latched closed; any violation is
      // terminal for the session.
      logger.record(.frameRejected)
      close(channel, reason: .counterViolation)
      return
    }

    guard let envelope = try? ListenerApplicationEnvelope.decode(plaintext),
      envelope.kind.isDeviceOriginated
    else {
      logger.record(.applicationMessageRejected)
      close(channel, reason: .protocolViolation)
      return
    }
    dispatch(envelope, channel: channel)
  }

  private func dispatch(_ envelope: ListenerApplicationEnvelope, channel: Channel) {
    guard let deviceID = frames?.deviceID, let sessionID = frames?.sessionID else {
      close(channel, reason: .authenticationFailed)
      return
    }
    dispatchInFlight = true
    let eventLoop = channel.eventLoop
    let observation = self.observation
    let commands = self.commands
    Task { [weak self] in
      let outcome = await Self.resolve(
        envelope,
        deviceID: deviceID,
        sessionID: sessionID,
        observation: observation,
        commands: commands
      )
      guard let handler = self else { return }
      eventLoop.execute {
        handler.apply(outcome, channel: channel)
      }
    }
  }

  /// Decodes and services one allowlisted message. Returns the batches to
  /// deliver, or the closed reason to close with.
  private static func resolve(
    _ envelope: ListenerApplicationEnvelope,
    deviceID: UUID,
    sessionID: UUID,
    observation: any ListenerObservationHandling,
    commands: any ListenerCommandHandling
  ) async -> ListenerObservationResolution {
    do {
      switch envelope.kind {
      case .observationSubscribe:
        let message: SecureObservationSubscribe
        do {
          message = try JSONDecoder().decode(
            SecureObservationSubscribe.self, from: envelope.payload)
        } catch {
          FileHandle.standardError.write(
            Data("codex-micro: subscribe.undecodable — \(error)\n".utf8))
          return .close(.protocolViolation)
        }
        let first = try await observation.subscribe(
          deviceID: deviceID,
          subscriptionID: message.subscriptionID,
          resumeCursor: message.resumeCursor
        )
        return .deliver(
          ListenerObservationOutcome(subscriptionID: message.subscriptionID, batches: [first]))
      case .observationAcknowledge:
        guard
          let message = try? JSONDecoder().decode(
            SecureObservationAcknowledgement.self, from: envelope.payload)
        else {
          return .close(.protocolViolation)
        }
        try await observation.acknowledge(
          deviceID: deviceID,
          subscriptionID: message.subscriptionID,
          cursor: message.cursor
        )
        // Draining after an acknowledgement is what keeps a subscription
        // moving: the device's ack is the credit that releases the next
        // batch, and the bounded backlog upstream stops this from running
        // away.
        let next = try await observation.nextBatch(deviceID: deviceID)
        return .deliver(
          ListenerObservationOutcome(
            subscriptionID: message.subscriptionID, batches: next.map { [$0] } ?? []))
      case .commandRequest:
        // The transport does not interpret the command: it decodes it
        // strictly, hands it to the gateway, and carries the closed result
        // back. Which commands run is decided behind the seam.
        guard let command = try? JSONDecoder().decode(ClientCommand.self, from: envelope.payload)
        else {
          return .close(.protocolViolation)
        }
        let outcome = await commands.execute(
          command: command, deviceID: deviceID, sessionID: sessionID)
        return .result(commandID: command.commandID, outcome: outcome)
      case .observationDelivery, .commandResult, .closeNotice:
        return .close(.protocolViolation)
      }
    } catch let refusal as ListenerObservationRefusal {
      FileHandle.standardError.write(
        Data("codex-micro: observation.refused — \(refusal)\n".utf8))
      return .close(refusal.closeReason)
    } catch {
      FileHandle.standardError.write(
        Data("codex-micro: observation.failed — \(type(of: error)):\(error)\n".utf8))
      return .close(.protocolViolation)
    }
  }

  private func apply(
    _ outcome: ListenerObservationResolution,
    channel: Channel
  ) {
    dispatchInFlight = false
    switch outcome {
    case .close(let reason):
      close(channel, reason: reason)
    case .deliver(let resolved):
      activeSubscriptionID = resolved.subscriptionID
      for batch in resolved.batches {
        guard deliver(batch, channel: channel) else { return }
      }
    case .result(let commandID, let outcome):
      deliverCommandResult(commandID: commandID, outcome: outcome, channel: channel)
    }
  }

  /// Seals and writes one closed command result.
  private func deliverCommandResult(
    commandID: UUID,
    outcome: ListenerCommandOutcome,
    channel: Channel
  ) {
    guard var current = frames,
      let result = try? outcome.wireResult(commandID: commandID),
      let body = try? JSONEncoder().encode(result),
      let envelope = try? ListenerApplicationEnvelope(kind: .commandResult, payload: body),
      let plaintext = try? envelope.encoded(),
      let sealed = try? current.outbound.seal(plaintext)
    else {
      logger.record(.applicationMessageRejected)
      close(channel, reason: .messageBoundsExceeded)
      return
    }
    frames = current
    var buffer = channel.allocator.buffer(capacity: sealed.count)
    buffer.writeBytes(sealed)
    channel.writeAndFlush(buffer, promise: nil)
    logger.record(.commandResultDelivered)
  }

  // MARK: - Outbound

  /// Seals and writes one already-authorized batch. Returns `false` when the
  /// connection was closed instead.
  @discardableResult
  public func deliver(_ batch: ListenerObservationBatch, channel: Channel) -> Bool {
    guard var current = frames else {
      close(channel, reason: .authenticationFailed)
      return false
    }
    guard let subscriptionID = activeSubscriptionID,
      let payload = try? batch.payload.encoded(),
      let delivery = try? SecureObservationDelivery(
        subscriptionID: subscriptionID,
        kind: batch.payload.deliveryKind,
        cursor: batch.cursor,
        payload: payload
      ),
      let body = try? JSONEncoder().encode(delivery),
      let envelope = try? ListenerApplicationEnvelope(kind: .observationDelivery, payload: body),
      let plaintext = try? envelope.encoded()
    else {
      // A batch that cannot be represented inside the declared bounds is a
      // host-side fault, never a silently truncated disclosure.
      logger.record(.applicationMessageRejected)
      close(channel, reason: .messageBoundsExceeded)
      return false
    }
    guard let sealed = try? current.outbound.seal(plaintext) else {
      logger.record(.frameRejected)
      close(channel, reason: .counterViolation)
      return false
    }
    frames = current
    var buffer = channel.allocator.buffer(capacity: sealed.count)
    buffer.writeBytes(sealed)
    channel.writeAndFlush(buffer, promise: nil)
    logger.record(.observationDelivered)
    return true
  }

  // MARK: - Teardown

  private func close(_ channel: Channel, reason: SecureCloseReason) {
    releaseState()
    guard var current = frames,
      let body = try? JSONEncoder().encode(SecureCloseNotice(reason: reason)),
      let envelope = try? ListenerApplicationEnvelope(kind: .closeNotice, payload: body),
      let plaintext = try? envelope.encoded(),
      let sealed = try? current.outbound.seal(plaintext)
    else {
      channel.close(promise: nil)
      return
    }
    frames = current
    var buffer = channel.allocator.buffer(capacity: sealed.count)
    buffer.writeBytes(sealed)
    channel.writeAndFlush(buffer).whenComplete { _ in
      channel.close(promise: nil)
    }
  }

  private func releaseState() {
    guard !released else { return }
    released = true
    let deviceID = frames?.deviceID
    let observation = self.observation
    let provider = frameProvider
    let connectionID = self.connectionID
    Task {
      await provider.discardFrames(connectionID: connectionID)
      if let deviceID {
        await observation.release(deviceID: deviceID)
      }
    }
  }
}

/// What servicing one device message resolved to.
enum ListenerObservationResolution: Sendable {
  /// Echo this subscription and send these already-authorized batches.
  case deliver(ListenerObservationOutcome)
  /// Send this closed command result.
  case result(commandID: UUID, outcome: ListenerCommandOutcome)
  /// Close with this post-authentication reason.
  case close(SecureCloseReason)
}

/// What servicing one device message produced.
struct ListenerObservationOutcome: Sendable {
  /// The subscription the device named, echoed on every delivery.
  let subscriptionID: UUID
  /// The already-authorized batches to seal and send, in order.
  let batches: [ListenerObservationBatch]
}
