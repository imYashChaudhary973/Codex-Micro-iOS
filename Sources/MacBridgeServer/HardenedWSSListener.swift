import CompanionProtocol
import Foundation
import NIOCore
import NIOHTTP1
import NIOTransportServices
import NIOWebSocket
import Network
import Security

/// The hardened direct-LAN TLS 1.3 / WSS listener (ADR §4, §5, §8, §9, §14).
///
/// It is **off by default**: a listener built from
/// ``ListenerConfiguration/disabled(binding:)`` fails closed with
/// ``ListenerStartupFailure/notEnabled``, and the only enabled factory is
/// explicitly test-only. Step 2.7 adds **no production Bonjour in any form**
/// and no Codex command path; Step 2.13 owns advertisement and the user
/// controls, and Step 2.9 owns the command gateway.
///
/// The lifecycle is one-shot — `idle → starting → running → stopping →
/// terminated` — and teardown attempts every step (stop accepting, close
/// every tracked child, close the server channel, shut the event-loop group
/// down) even when an earlier step fails, because NIOTS does not cascade a
/// listener close to its children.
public actor HardenedWSSListener {
  private static let upgradeDeadlineHandlerName = "codex-micro.listener.upgrade-deadline"
  private static let preUpgradeLimitHandlerName = "codex-micro.listener.pre-upgrade-bytes"

  private struct Resources: Sendable {
    let serverChannel: Channel
    let listener: NWListener
  }

  private let configuration: ListenerConfiguration
  private let prerequisites: ListenerPrerequisites
  private let ceilings: ListenerCeilings
  private let group: NIOTSEventLoopGroup
  private let admission: ListenerAdmissionController
  private let registry = ListenerChildRegistry()
  private let rejections = ListenerRejectionRecorder()
  private var lifecycle = ListenerLifecycleStateMachine()
  private var resources: Resources?
  private var groupShutdown = false
  private var cleanupInProgress = false
  private var cleanupFailed = false
  private var stopWaiters: [CheckedContinuation<Void, Never>] = []

  /// Creates a listener. Nothing binds until ``start()`` is called, and
  /// ``start()`` binds nothing unless every prerequisite passes.
  public init(configuration: ListenerConfiguration, prerequisites: ListenerPrerequisites) {
    self.configuration = configuration
    self.prerequisites = prerequisites
    self.ceilings = configuration.ceilings
    self.group = NIOTSEventLoopGroup(loopCount: 1)
    self.admission = ListenerAdmissionController(
      ceilings: configuration.ceilings,
      now: configuration.now
    )
  }

  /// Starts the listener and returns the bound endpoint.
  ///
  /// Order: lifecycle claim, ceiling validation, prerequisite probes, bind
  /// revalidation, live-interface pinning, bind, bound-address verification.
  /// Any failure terminates the listener; there is no partially started
  /// state and no restart.
  @discardableResult
  public func start() async throws -> ListenerEndpoint {
    try lifecycle.beginStart()

    let identity: ListenerServingIdentity
    do {
      _ = try ceilings.validated()
      identity = try await prerequisites.resolve(isEnabled: configuration.isEnabled)
    } catch let failure as ListenerStartupFailure {
      configuration.logger.record(.prerequisiteUnavailable)
      configuration.logger.record(.listenerStartFailed)
      await terminate(resources: nil)
      throw ListenerError.startupDenied(failure)
    }

    let socketAddress: SocketAddress
    do {
      socketAddress = try configuration.binding.revalidated(policy: configuration.interfacePolicy)
    } catch {
      configuration.logger.record(.interfaceDenied)
      configuration.logger.record(.listenerStartFailed)
      await terminate(resources: nil)
      throw ListenerError.invalidBinding
    }

    let liveInterface = await prerequisites.liveInterface.resolveLiveInterface(
      bsdName: configuration.binding.interface.identifier
    )
    if liveInterface == nil, configuration.binding.interface.kind != .loopback {
      configuration.logger.record(.interfaceUnavailable)
      configuration.logger.record(.listenerStartFailed)
      await terminate(resources: nil)
      throw ListenerError.startupDenied(.liveInterfaceUnavailable)
    }

    var boundChannel: Channel?
    do {
      let bootstrap = try makeBootstrap(identity: identity, liveInterface: liveInterface)
      let channel = try await bootstrap.bind(to: socketAddress).get()
      boundChannel = channel
      guard channel.localAddress?.ipAddress == socketAddress.ipAddress else {
        throw ListenerError.invalidBinding
      }
      guard let port = channel.localAddress?.port else {
        throw ListenerError.portUnavailable
      }
      guard let listener = try await channel.getOption(NIOTSChannelOptions.listener).get() else {
        throw ListenerError.listenerUnavailable
      }
      resources = Resources(serverChannel: channel, listener: listener)
      guard lifecycle.completeStart() else {
        throw ListenerError.startCancelled
      }
      configuration.logger.record(.listenerReady)
      return ListenerEndpoint(
        host: configuration.binding.host,
        port: port,
        spkiFingerprint: identity.spkiFingerprint
      )
    } catch {
      if resources == nil, let boundChannel {
        do {
          try await boundChannel.close()
        } catch {
          cleanupFailed = true
        }
      }
      configuration.logger.record(.listenerStartFailed)
      if lifecycle.phase != .terminated {
        await terminate(resources: resources)
      }
      if cleanupFailed { throw ListenerError.cleanupFailed }
      throw error
    }
  }

  /// Publishes the Bonjour record on the bound listener.
  ///
  /// Advertising is a property of the `NWListener` the bind produced, so only
  /// this actor can do it — which is why nothing did: the only publisher that
  /// existed was the disabled stub, and it reported success. A device could
  /// therefore never discover a bridge that reported itself as advertising.
  ///
  /// Called after the bind and before the LAN control reports success, so a
  /// record is never published for a listener that is not accepting.
  public func advertise() throws {
    guard let resources else { throw ListenerError.listenerUnavailable }
    resources.listener.service = ListenerBonjourRecord.service()
  }

  /// Withdraws the record, leaving the listener bound.
  public func withdraw() {
    resources?.listener.service = nil
  }

  /// Stops the listener and joins teardown. Duplicate stops are safe; a
  /// stop racing a start makes the start fail rather than leaking a
  /// listener.
  public func stop() async throws {
    if lifecycle.phase == .terminated {
      if cleanupFailed { throw ListenerError.cleanupFailed }
      return
    }
    let cleanupNow = lifecycle.requestStop()
    admission.stopAccepting()
    if cleanupNow {
      await terminate(resources: resources)
      if cleanupFailed { throw ListenerError.cleanupFailed }
      return
    }
    if lifecycle.phase != .terminated {
      await withCheckedContinuation { continuation in
        stopWaiters.append(continuation)
      }
    }
    if cleanupFailed { throw ListenerError.cleanupFailed }
  }

  /// A sanitized lifecycle snapshot.
  public func snapshot() -> ListenerSnapshot {
    ListenerSnapshot(
      phase: lifecycle.phase,
      activeChildren: registry.count,
      authenticatedChildren: registry.authenticatedCount,
      bonjourPublished: false,
      groupShutdown: groupShutdown
    )
  }

  /// The most recent upgrade rejection code, for deterministic assertions.
  /// It is diagnostic only and never travels to a peer.
  public func lastUpgradeRejection() -> ListenerUpgradeRejection? {
    rejections.lastUpgradeRejection
  }

  /// The most recent frame-policy violation code, for deterministic
  /// assertions.
  public func lastFrameViolation() -> ListenerFrameViolation? {
    rejections.lastFrameViolation
  }

  /// The most recent admission rejection code, for deterministic
  /// assertions.
  public func lastAdmissionRejection() -> ListenerAdmissionRejection? {
    rejections.lastAdmissionRejection
  }

  private func makeBootstrap(
    identity: ListenerServingIdentity,
    liveInterface: NWInterface?
  ) throws -> NIOTSListenerBootstrap {
    let tlsOptions = try Self.makeTLSOptions(identity: identity)
    let tcpOptions = NWProtocolTCP.Options()
    tcpOptions.enableFastOpen = false
    tcpOptions.enableKeepalive = true
    tcpOptions.keepaliveIdle = 30
    tcpOptions.keepaliveInterval = 10
    tcpOptions.keepaliveCount = 3

    let kind = configuration.binding.interface.kind
    let admission = self.admission
    let registry = self.registry
    let rejections = self.rejections
    let logger = configuration.logger
    let handshake = configuration.handshake
    let observation = configuration.observation
    let commands = configuration.commands
    let frameProvider = configuration.frameProvider
    let ceilings = self.ceilings
    let now = configuration.now

    return NIOTSListenerBootstrap(group: group)
      .bindTimeout(.seconds(5))
      .tcpOptions(tcpOptions)
      .tlsOptions(tlsOptions)
      .configureNWParameters { parameters in
        parameters.allowFastOpen = false
        parameters.includePeerToPeer = false
        parameters.multipathServiceType = .disabled
        parameters.preferNoProxies = true
        parameters.prohibitExpensivePaths = true
        parameters.prohibitedInterfaceTypes = [.cellular, .other]
        switch kind {
        case .wifi:
          parameters.requiredInterfaceType = .wifi
        case .ethernet:
          parameters.requiredInterfaceType = .wiredEthernet
        case .loopback:
          parameters.requiredInterfaceType = .loopback
          parameters.prohibitedInterfaceTypes = [.cellular]
        case .vpn, .tunnel, .cellular, .peerToPeer, .other, .wildcard:
          parameters.requiredInterfaceType = .other
        }
        // ADR §8/§16: pin the exact live interface object when one resolved,
        // so an address that later appears on a different interface cannot
        // silently carry the listener.
        if let liveInterface {
          parameters.requiredInterface = liveInterface
        }
      }
      .childChannelInitializer { channel in
        Self.configureChild(
          channel: channel,
          admission: admission,
          registry: registry,
          rejections: rejections,
          logger: logger,
          handshake: handshake,
          observation: observation,
          commands: commands,
          frameProvider: frameProvider,
          ceilings: ceilings,
          now: now
        )
      }
  }

  private static func configureChild(
    channel: Channel,
    admission: ListenerAdmissionController,
    registry: ListenerChildRegistry,
    rejections: ListenerRejectionRecorder,
    logger: any ListenerLogging,
    handshake: any ListenerHandshakeHandling,
    observation: any ListenerObservationHandling = DenyingListenerObservationHandler(),
    commands: any ListenerCommandHandling = DenyingListenerCommandHandler(),
    frameProvider: any ListenerSessionFrameProviding = DenyingListenerSessionFrameProvider(),
    ceilings: ListenerCeilings,
    now: @escaping @Sendable () -> UInt64
  ) -> EventLoopFuture<Void> {
    let source = ListenerSourceKey(
      numericAddress: channel.remoteAddress?.ipAddress ?? "unknown"
    )
    let ticket: ListenerConnectionTicket
    switch admission.admit(source: source) {
    case .failure(let rejection):
      rejections.recordAdmission(rejection)
      logger.record(.connectionRefused)
      return channel.close()
    case .success(let granted):
      ticket = granted
    }
    guard registry.register(channel, ticket: ticket) else {
      ticket.release()
      logger.record(.connectionRefused)
      return channel.close()
    }
    logger.record(.connectionAccepted)
    channel.closeFuture.whenComplete { _ in
      ticket.release()
      registry.unregister(channel)
      logger.record(.connectionClosed)
    }

    let connectionID = UUID()
    // Both handlers sit ahead of the HTTP decoder: the byte limiter counts
    // raw bytes, and neither the limiter nor the deadline is reachable from
    // the post-upgrade pipeline. A plain (non-upgrade) request therefore
    // still meets a byte budget and a deadline even though it never reaches
    // the upgrade policy.
    let preUpgradeLimiter = ListenerPreUpgradeByteLimitHandler(
      maximumBytes: ceilings.maxPreUpgradeBytes
    ) {
      logger.record(.preUpgradeBudgetExceeded)
    }
    let deadlineHandler = ListenerUpgradeDeadlineHandler(
      deadline: .seconds(Int64(ceilings.upgradeDeadlineSeconds))
    ) {
      logger.record(.upgradeDeadlineElapsed)
    }
    do {
      try channel.pipeline.syncOperations.addHandler(
        preUpgradeLimiter,
        name: preUpgradeLimitHandlerName
      )
      try channel.pipeline.syncOperations.addHandler(
        deadlineHandler,
        name: upgradeDeadlineHandlerName
      )
    } catch {
      return channel.close()
    }
    return configureHTTPPipeline(
      channel: channel,
      connectionID: connectionID,
      source: source,
      admission: admission,
      ticket: ticket,
      rejections: rejections,
      logger: logger,
      handshake: handshake,
      ceilings: ceilings,
      now: now
    )
  }

  private static func configureHTTPPipeline(
    channel: Channel,
    connectionID: UUID,
    source: ListenerSourceKey,
    admission: ListenerAdmissionController,
    ticket: ListenerConnectionTicket,
    rejections: ListenerRejectionRecorder,
    logger: any ListenerLogging,
    handshake: any ListenerHandshakeHandling,
    observation: any ListenerObservationHandling = DenyingListenerObservationHandler(),
    commands: any ListenerCommandHandling = DenyingListenerCommandHandler(),
    frameProvider: any ListenerSessionFrameProviding = DenyingListenerSessionFrameProvider(),
    ceilings: ListenerCeilings,
    now: @escaping @Sendable () -> UInt64
  ) -> EventLoopFuture<Void> {
    let policy = ListenerUpgradePolicy()
    let upgrader = NIOWebSocketServerUpgrader(
      maxFrameSize: SecureTransportLimits.maxFrameBytes,
      automaticErrorHandling: true,
      shouldUpgrade: { channel, request in
        switch policy.evaluate(request) {
        case .success(let headers):
          return channel.eventLoop.makeSucceededFuture(headers)
        case .failure(let rejection):
          rejections.recordUpgrade(rejection)
          logger.record(.upgradeRejected)
          channel.eventLoop.execute { channel.close(promise: nil) }
          return channel.eventLoop.makeSucceededFuture(nil)
        }
      },
      upgradePipelineHandler: { channel, _ in
        ListenerPipeline.configureWebSocket(
          channel: channel,
          connectionID: connectionID,
          source: source,
          admission: admission,
          ticket: ticket,
          rejections: rejections,
          logger: logger,
          handshake: handshake,
          ceilings: ceilings,
          now: now
        )
      }
    )
    let configuration: NIOHTTPServerUpgradeSendableConfiguration = (
      upgraders: [upgrader],
      completionHandler: { context in
        context.pipeline.fireUserInboundEventTriggered(ListenerUpgradeCompleted())
      }
    )
    var limits = NIOHTTPDecoderLimitConfiguration()
    limits.maxHeaderFieldSize = SecureTransportLimits.maxHeaderFieldBytes
    limits.maxHeaderListSize = SecureTransportLimits.maxHeaderTotalBytes
    limits.maxHeaderFieldCount = SecureTransportLimits.maxHeaderFieldCount
    return channel.pipeline.configureHTTPServerPipeline(
      withPipeliningAssistance: false,
      withServerUpgrade: configuration,
      withErrorHandling: true,
      withOutboundHeaderValidation: true,
      withDecoderLimitConfiguration: limits
    )
  }

  /// TLS 1.3-only Network.framework policy (ADR §5).
  ///
  /// Exactly one protocol version, exactly one cipher suite, and tickets,
  /// resumption, False Start, and fallback all disabled through public API.
  /// Client certificates are not requested: TLS is not the authorization
  /// layer (plan §2 invariant 9), authentication is the sealed application
  /// handshake, and the client's own trust is SPKI pinning only.
  static func makeTLSOptions(identity: ListenerServingIdentity) throws -> NWProtocolTLS.Options {
    let tlsOptions = NWProtocolTLS.Options()
    let options = tlsOptions.securityProtocolOptions
    guard let secIdentity = sec_identity_create(identity.secIdentity) else {
      throw ListenerError.identityBridgeFailed
    }
    sec_protocol_options_set_local_identity(options, secIdentity)
    sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_append_tls_ciphersuite(options, .AES_128_GCM_SHA256)
    sec_protocol_options_set_tls_tickets_enabled(options, false)
    sec_protocol_options_set_tls_resumption_enabled(options, false)
    sec_protocol_options_set_tls_false_start_enabled(options, false)
    sec_protocol_options_set_tls_is_fallback_attempt(options, false)
    sec_protocol_options_set_peer_authentication_required(options, false)
    sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
    return tlsOptions
  }

  private func terminate(resources: Resources?) async {
    guard !cleanupInProgress else { return }
    cleanupInProgress = true
    _ = lifecycle.requestStop()
    admission.stopAccepting()

    var failed = cleanupFailed
    for child in registry.beginStopping() {
      do {
        try await child.close()
      } catch let error as ChannelError where error == .alreadyClosed {
        continue
      } catch {
        failed = true
      }
    }
    if let serverChannel = resources?.serverChannel {
      do {
        try await serverChannel.close()
      } catch let error as ChannelError where error == .alreadyClosed {
        // Already closed by a racing teardown; not a cleanup failure.
      } catch {
        failed = true
      }
    }
    if !groupShutdown {
      do {
        try await group.shutdownGracefully()
        groupShutdown = true
      } catch {
        failed = true
        groupShutdown = false
      }
    }
    if registry.count != 0 {
      failed = true
    }
    cleanupFailed = failed
    self.resources = nil
    lifecycle.terminate()
    cleanupInProgress = false
    configuration.logger.record(failed ? .listenerCleanupFailed : .listenerStopped)
    let waiters = stopWaiters
    stopWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }
}

/// Post-upgrade pipeline assembly (ADR §9).
///
/// Order is load-bearing and asserted by test. Head to tail:
///
/// 1. ``ListenerOutboundBoundHandler`` — head-most, so **every** outbound
///    frame is accounted for: application payloads written from the tail,
///    the pongs the frame policy emits, and the server's keep-alive pings.
/// 2. ``ListenerFragmentAggregator`` — reassembly and fragment bounds.
/// 3. ``ListenerInboundRateHandler`` — meters one reassembled message, and
///    every peer-driven control frame, against the per-connection ceilings.
/// 4. ``ListenerKeepAliveHandler`` — sees pongs before they are consumed and
///    emits pings head-ward through the outbound accounting.
/// 5. ``ListenerBinaryFramePolicy`` — binary-only policy, ping replies, and
///    the frame/bytes boundary.
/// 6. ``ListenerHandshakeGateHandler`` — the pre-authentication allowlist.
/// 7. ``ListenerObservationHandler`` — tail-most, and reachable only after
///    authentication: it opens every inbound sealed frame and seals every
///    outbound delivery. It sits behind the gate so no unauthenticated byte
///    can reach a frame codec, and behind every ceiling so sealed traffic is
///    metered exactly like handshake traffic.
///
/// Application bytes therefore cross every bound before any handshake state
/// machine sees them, and nothing the peer can drive reaches the wire
/// without passing the outbound bound.
public enum ListenerPipeline {
  /// Installs the post-upgrade handler chain on `channel`.
  public static func configureWebSocket(
    channel: Channel,
    connectionID: UUID,
    source: ListenerSourceKey,
    admission: ListenerAdmissionController,
    ticket: ListenerConnectionTicket,
    rejections: ListenerRejectionRecorder,
    logger: any ListenerLogging,
    handshake: any ListenerHandshakeHandling,
    observation: any ListenerObservationHandling = DenyingListenerObservationHandler(),
    commands: any ListenerCommandHandling = DenyingListenerCommandHandler(),
    frameProvider: any ListenerSessionFrameProviding = DenyingListenerSessionFrameProvider(),
    ceilings: ListenerCeilings,
    now: @escaping @Sendable () -> UInt64
  ) -> EventLoopFuture<Void> {
    let meter = ListenerInboundRateMeter(
      maxMessagesPerSecond: ceilings.maxInboundMessagesPerSecond,
      maxBytesPerSecond: ceilings.maxInboundBytesPerSecond,
      now: now
    )
    let handlers: [any ChannelHandler & Sendable] = [
      ListenerOutboundBoundHandler(
        maxFrames: ceilings.maxOutboundQueueFrames,
        maxBytes: ceilings.maxOutboundQueueBytes,
        nonWritableLimit: .seconds(Int64(ceilings.maxNonWritableSeconds)),
        onQueueExceeded: { logger.record(.outboundQueueExceeded) },
        onSlowConsumer: { logger.record(.slowConsumerClosed) }
      ),
      ListenerFragmentAggregator(
        maximumFragmentCount: SecureTransportLimits.maxFragmentsPerMessage,
        maximumMessageBytes: SecureTransportLimits.maxMessageBytes,
        onViolation: { violation in
          rejections.recordFrame(violation)
          logger.record(.frameRejected)
        }
      ),
      ListenerInboundRateHandler(meter: meter) {
        logger.record(.inboundRateExceeded)
      },
      ListenerKeepAliveHandler(
        pingCadence: .seconds(Int64(ceilings.pingCadenceSeconds)),
        pongDeadline: .seconds(Int64(ceilings.pongDeadlineSeconds)),
        idleExpiry: .seconds(Int64(ceilings.idleExpirySeconds)),
        onPongDeadline: { logger.record(.pongDeadlineElapsed) },
        onIdleExpiry: { logger.record(.idleExpired) }
      ),
      ListenerBinaryFramePolicy(
        maximumMessageBytes: SecureTransportLimits.maxMessageBytes,
        onViolation: { violation in
          rejections.recordFrame(violation)
          logger.record(.frameRejected)
        }
      ),
      ListenerHandshakeGateHandler(
        connectionID: connectionID,
        source: source,
        admission: admission,
        ticket: ticket,
        handshake: handshake,
        authenticationDeadline: .seconds(Int64(ceilings.authenticationDeadlineSeconds)),
        silenceBudget: .seconds(Int64(ceilings.unauthenticatedSilenceSeconds)),
        logger: logger
      ),
      ListenerObservationHandler(
        connectionID: connectionID,
        observation: observation,
        commands: commands,
        frameProvider: frameProvider,
        logger: logger
      ),
    ]
    return channel.pipeline.addHandlers(handlers)
  }
}

/// Registry-based child tracking (ADR §14: NIOTS does not cascade a listener
/// close to its children, so teardown is registry-driven).
///
/// A child arriving after teardown begins is refused and closed.
final class ListenerChildRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var accepting = true
  private var channels: [ObjectIdentifier: Channel] = [:]
  private var tickets: [ObjectIdentifier: ListenerConnectionTicket] = [:]

  func register(_ channel: Channel, ticket: ListenerConnectionTicket) -> Bool {
    lock.withLock {
      guard accepting else { return false }
      let key = ObjectIdentifier(channel)
      channels[key] = channel
      tickets[key] = ticket
      return true
    }
  }

  func unregister(_ channel: Channel) {
    lock.withLock {
      let key = ObjectIdentifier(channel)
      channels.removeValue(forKey: key)
      tickets.removeValue(forKey: key)
    }
  }

  func beginStopping() -> [Channel] {
    lock.withLock {
      accepting = false
      return Array(channels.values)
    }
  }

  var count: Int {
    lock.withLock { channels.count }
  }

  var authenticatedCount: Int {
    lock.withLock { tickets.values.filter { $0.isAuthenticated }.count }
  }
}

/// Records the most recent closed rejection codes for deterministic
/// assertions. Nothing recorded here is peer-derived content.
public final class ListenerRejectionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var upgrade: ListenerUpgradeRejection?
  private var frame: ListenerFrameViolation?
  private var admission: ListenerAdmissionRejection?

  /// Creates an empty recorder.
  public init() {}

  func recordUpgrade(_ rejection: ListenerUpgradeRejection) {
    lock.withLock { upgrade = rejection }
  }

  func recordFrame(_ violation: ListenerFrameViolation) {
    lock.withLock { frame = violation }
  }

  func recordAdmission(_ rejection: ListenerAdmissionRejection) {
    lock.withLock { admission = rejection }
  }

  /// The most recent upgrade rejection.
  public var lastUpgradeRejection: ListenerUpgradeRejection? {
    lock.withLock { upgrade }
  }

  /// The most recent frame violation.
  public var lastFrameViolation: ListenerFrameViolation? {
    lock.withLock { frame }
  }

  /// The most recent admission rejection.
  public var lastAdmissionRejection: ListenerAdmissionRejection? {
    lock.withLock { admission }
  }
}
