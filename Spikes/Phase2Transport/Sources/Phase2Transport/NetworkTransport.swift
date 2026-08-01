import Foundation
import NIOCore
import NIOTransportServices
import Network
import Security

public enum NetworkTransportError: Error, Equatable {
  case alreadyPublished
  case alreadyStarted
  case cleanupFailed
  case identityBridgeFailed
  case invalidBinding
  case listenerUnavailable
  case notStarted
  case portUnavailable
  case publicationRemoved
  case publicationStopped
  case publicationTimedOut
  case startCancelled
  case terminated
}

public enum TransportLifecyclePhase: String, Equatable, Sendable {
  case idle
  case starting
  case running
  case publishing
  case stopping
  case terminated
}

public struct TransportLifecycleStateMachine: Equatable, Sendable {
  public private(set) var phase: TransportLifecyclePhase = .idle
  public private(set) var stopRequested = false

  public init() {}

  public mutating func beginStart() throws {
    guard phase == .idle else {
      throw phase == .terminated ? NetworkTransportError.terminated : .alreadyStarted
    }
    phase = .starting
  }

  public mutating func completeStart() -> Bool {
    guard phase == .starting, !stopRequested else {
      phase = .stopping
      return false
    }
    phase = .running
    return true
  }

  public mutating func beginPublish() throws {
    guard phase == .running else {
      throw phase == .terminated ? NetworkTransportError.terminated : .notStarted
    }
    phase = .publishing
  }

  public mutating func completePublish() -> Bool {
    guard phase == .publishing, !stopRequested else {
      phase = .stopping
      return false
    }
    phase = .running
    return true
  }

  public mutating func requestStop() -> Bool {
    stopRequested = true
    switch phase {
    case .idle, .running:
      phase = .stopping
      return true
    case .starting, .publishing:
      phase = .stopping
      return false
    case .stopping, .terminated:
      return false
    }
  }

  public mutating func terminate() {
    stopRequested = true
    phase = .terminated
  }
}

public struct TransportLifecycleSnapshot: Equatable, Sendable {
  public let phase: TransportLifecyclePhase
  public let activeChildren: Int
  public let bonjourPublished: Bool
  public let groupShutdown: Bool

  public init(
    phase: TransportLifecyclePhase,
    activeChildren: Int,
    bonjourPublished: Bool,
    groupShutdown: Bool
  ) {
    self.phase = phase
    self.activeChildren = activeChildren
    self.bonjourPublished = bonjourPublished
    self.groupShutdown = groupShutdown
  }
}

public enum ContentNeutralBonjourService {
  public static let name = "Phase2TransportSpike"
  public static let type = "_codexmicro-spike._tcp"
  public static let domain = "local."
  public static let txtRecord = NWTXTRecord(["mode": "spike", "v": "1"])

  public static func make() -> NWListener.Service {
    var service = NWListener.Service(
      name: name,
      type: type,
      domain: domain,
      txtRecord: txtRecord
    )
    service.noAutoRename = true
    return service
  }
}

enum BonjourRegistrationEvent: Equatable, Sendable {
  case added
  case removed
  case stopped
  case timedOut
}

enum BonjourRegistrationAction: Equatable, Sendable {
  case none
  case published
  case removeService(NetworkTransportError?)
  case unexpectedRemoval
}

struct BonjourRegistrationStateMachine: Equatable, Sendable {
  enum State: Equatable, Sendable {
    case idle
    case pending
    case published
    case stopped
  }

  private(set) var state: State = .idle

  mutating func begin() throws {
    guard state == .idle else { throw NetworkTransportError.alreadyPublished }
    state = .pending
  }

  mutating func receive(_ event: BonjourRegistrationEvent) -> BonjourRegistrationAction {
    switch (state, event) {
    case (.pending, .added):
      state = .published
      return .published
    case (.pending, .removed):
      state = .stopped
      return .removeService(.publicationRemoved)
    case (.pending, .stopped):
      state = .stopped
      return .removeService(.publicationStopped)
    case (.pending, .timedOut):
      state = .stopped
      return .removeService(.publicationTimedOut)
    case (.published, .removed):
      state = .stopped
      return .unexpectedRemoval
    case (.published, .stopped):
      state = .stopped
      return .removeService(nil)
    case (.published, .timedOut), (.published, .added), (.stopped, _), (.idle, _):
      return .none
    }
  }
}

final class BonjourRegistrationWaiter: @unchecked Sendable {
  let id = UUID()

  private let lock = NSLock()
  private let queue: DispatchQueue
  private let timeout: DispatchTimeInterval
  private let onUnexpectedRemoval: @Sendable (UUID) -> Void
  private weak var listener: NWListener?
  private var continuation: CheckedContinuation<Void, Error>?
  private var machine = BonjourRegistrationStateMachine()
  private var timeoutWorkItem: DispatchWorkItem?
  private var stoppedBeforePublish = false

  init(
    queue: DispatchQueue = DispatchQueue(label: "phase2-bonjour-timeout"),
    timeout: DispatchTimeInterval = .seconds(5),
    onUnexpectedRemoval: @escaping @Sendable (UUID) -> Void
  ) {
    self.queue = queue
    self.timeout = timeout
    self.onUnexpectedRemoval = onUnexpectedRemoval
  }

  var isPublished: Bool {
    lock.withLock { machine.state == .published }
  }

  func publish(listener: NWListener, service: NWListener.Service) async throws {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let workItem = DispatchWorkItem { [weak self] in
          self?.receive(.timedOut)
        }
        do {
          try lock.withLock {
            guard !stoppedBeforePublish else {
              throw NetworkTransportError.publicationStopped
            }
            try machine.begin()
            self.listener = listener
            self.continuation = continuation
            timeoutWorkItem = workItem
            listener.serviceRegistrationUpdateHandler = { [weak self] change in
              switch change {
              case .add:
                self?.receive(.added)
              case .remove:
                self?.receive(.removed)
              @unknown default:
                self?.receive(.removed)
              }
            }
            listener.service = service
          }
        } catch {
          continuation.resume(throwing: error)
          return
        }
        queue.asyncAfter(deadline: .now() + timeout, execute: workItem)
      }
    } onCancel: { [weak self] in
      self?.stop()
    }
  }

  func stop() {
    let shouldReceive = lock.withLock {
      if machine.state == .idle {
        stoppedBeforePublish = true
        return false
      }
      return true
    }
    if shouldReceive {
      receive(.stopped)
    }
  }

  private func receive(_ event: BonjourRegistrationEvent) {
    let resolution:
      (
        BonjourRegistrationAction,
        CheckedContinuation<Void, Error>?,
        DispatchWorkItem?,
        NWListener?
      ) = lock.withLock {
        let action = machine.receive(event)
        guard action != .none else { return (.none, nil, nil, nil) }
        let continuation = self.continuation
        if action == .published || action.isTerminal {
          self.continuation = nil
        }
        let timeoutWorkItem = self.timeoutWorkItem
        if action == .published || action.isTerminal {
          self.timeoutWorkItem = nil
        }
        return (action, continuation, timeoutWorkItem, listener)
      }

    switch resolution.0 {
    case .none:
      return
    case .published:
      resolution.2?.cancel()
      resolution.1?.resume()
    case .removeService(let error):
      resolution.2?.cancel()
      resolution.3?.serviceRegistrationUpdateHandler = nil
      resolution.3?.service = nil
      if let error {
        resolution.1?.resume(throwing: error)
      }
    case .unexpectedRemoval:
      resolution.2?.cancel()
      resolution.3?.serviceRegistrationUpdateHandler = nil
      onUnexpectedRemoval(id)
    }
  }
}

extension BonjourRegistrationAction {
  fileprivate var isTerminal: Bool {
    switch self {
    case .removeService, .unexpectedRemoval:
      return true
    case .none, .published:
      return false
    }
  }
}

public struct RunningTransportEndpoint: Equatable, Sendable {
  public let host: String
  public let port: Int
  public let spkiSHA256: Data

  public init(host: String, port: Int, spkiSHA256: Data) {
    self.host = host
    self.port = port
    self.spkiSHA256 = spkiSHA256
  }
}

public final class HandshakeDeadlineHandler: ChannelInboundHandler, RemovableChannelHandler,
  @unchecked Sendable
{
  public typealias InboundIn = NIOAny

  private let timeout: TimeAmount
  private var deadlineTask: Scheduled<Void>?

  public init(timeout: TimeAmount) {
    self.timeout = timeout
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    let channel = context.channel
    deadlineTask = context.eventLoop.scheduleTask(in: timeout) {
      channel.close(promise: nil)
    }
  }

  public func handlerRemoved(context: ChannelHandlerContext) {
    deadlineTask?.cancel()
    deadlineTask = nil
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    context.fireChannelRead(data)
  }

  public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if event is WebSocketUpgradeCompleted {
      deadlineTask?.cancel()
      deadlineTask = nil
      context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
    } else {
      context.fireUserInboundEventTriggered(event)
    }
  }

  public func channelInactive(context: ChannelHandlerContext) {
    deadlineTask?.cancel()
    deadlineTask = nil
    context.fireChannelInactive()
  }
}

private final class ChildChannelRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var accepting = true
  private var channels: [ObjectIdentifier: Channel] = [:]

  func register(_ channel: Channel) -> Bool {
    lock.withLock {
      guard accepting else { return false }
      channels[ObjectIdentifier(channel)] = channel
      return true
    }
  }

  func unregister(_ channel: Channel) {
    _ = lock.withLock {
      channels.removeValue(forKey: ObjectIdentifier(channel))
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
}

private final class UpgradeRejectionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var rejection: WebSocketUpgradeRejection?

  func record(_ rejection: WebSocketUpgradeRejection) {
    lock.withLock { self.rejection = rejection }
  }

  var value: WebSocketUpgradeRejection? {
    lock.withLock { rejection }
  }
}

public actor NIOTSTLSWebSocketServer {
  private static let deadlineHandlerName = "phase2-handshake-deadline"

  private struct Resources: Sendable {
    let serverChannel: Channel
    let listener: NWListener
  }

  private let group: NIOTSEventLoopGroup
  private let limiter: ConnectionLimiter
  private let childRegistry = ChildChannelRegistry()
  private let rejectionRecorder = UpgradeRejectionRecorder()
  private var lifecycle = TransportLifecycleStateMachine()
  private var resources: Resources?
  private var publication: BonjourRegistrationWaiter?
  private var groupShutdown = false
  private var cleanupInProgress = false
  private var cleanupFailed = false
  private var stopWaiters: [CheckedContinuation<Void, Never>] = []

  public init(connectionLimit: Int = 4) {
    self.group = NIOTSEventLoopGroup(loopCount: 1)
    self.limiter = ConnectionLimiter(maximum: connectionLimit)
  }

  public func start(
    binding: InterfaceBinding,
    policy: InterfacePolicy,
    certificate: TLSCertificateMaterial
  ) async throws -> RunningTransportEndpoint {
    try lifecycle.beginStart()
    let socketAddress: SocketAddress
    do {
      socketAddress = try binding.revalidated(policy: policy)
    } catch {
      await terminate(resources: nil)
      throw NetworkTransportError.invalidBinding
    }

    var boundChannel: Channel?
    do {
      let tlsOptions = try makeTLSOptions(certificate: certificate)
      let tcpOptions = NWProtocolTCP.Options()
      tcpOptions.enableFastOpen = false
      tcpOptions.enableKeepalive = true
      tcpOptions.keepaliveIdle = 30
      tcpOptions.keepaliveInterval = 10
      tcpOptions.keepaliveCount = 3

      let limiter = self.limiter
      let registry = childRegistry
      let recorder = rejectionRecorder
      let bootstrap = NIOTSListenerBootstrap(group: group)
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
          switch binding.interface.kind {
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
        }
        .childChannelInitializer { channel in
          guard let lease = limiter.acquire(), registry.register(channel) else {
            return channel.close()
          }
          channel.closeFuture.whenComplete { _ in
            lease.release()
            registry.unregister(channel)
          }
          return channel.pipeline.addHandler(
            HandshakeDeadlineHandler(timeout: .seconds(5)),
            name: Self.deadlineHandlerName
          ).flatMap {
            HardenedWebSocketPipeline.configure(
              channel: channel,
              rejectionObserver: { rejection in
                recorder.record(rejection)
              }
            )
          }
        }

      let channel = try await bootstrap.bind(to: socketAddress).get()
      boundChannel = channel
      guard channel.localAddress?.ipAddress == socketAddress.ipAddress else {
        throw NetworkTransportError.invalidBinding
      }
      guard let port = channel.localAddress?.port else {
        throw NetworkTransportError.portUnavailable
      }
      guard let listener = try await channel.getOption(NIOTSChannelOptions.listener).get() else {
        throw NetworkTransportError.listenerUnavailable
      }
      let resources = Resources(serverChannel: channel, listener: listener)
      self.resources = resources
      guard lifecycle.completeStart() else {
        throw NetworkTransportError.startCancelled
      }
      return RunningTransportEndpoint(
        host: binding.host,
        port: port,
        spkiSHA256: certificate.spkiSHA256
      )
    } catch {
      if resources == nil, let boundChannel {
        do {
          try await boundChannel.close()
        } catch {
          cleanupFailed = true
        }
      }
      if lifecycle.phase != .terminated {
        await terminate(resources: resources)
      }
      if cleanupFailed {
        throw NetworkTransportError.cleanupFailed
      }
      throw error
    }
  }

  public func publishBonjour() async throws {
    try lifecycle.beginPublish()
    guard let resources else {
      await terminate(resources: nil)
      throw NetworkTransportError.notStarted
    }

    let waiter = BonjourRegistrationWaiter(onUnexpectedRemoval: { [weak self] waiterID in
      Task {
        await self?.publicationWasRemoved(expectedID: waiterID)
      }
    })
    publication = waiter
    do {
      try await waiter.publish(
        listener: resources.listener,
        service: ContentNeutralBonjourService.make()
      )
      guard lifecycle.completePublish() else {
        waiter.stop()
        throw NetworkTransportError.publicationStopped
      }
    } catch {
      if lifecycle.phase != .terminated {
        await terminate(resources: resources)
      }
      if cleanupFailed {
        throw NetworkTransportError.cleanupFailed
      }
      throw error
    }
  }

  public func stop() async throws {
    if lifecycle.phase == .terminated {
      if cleanupFailed { throw NetworkTransportError.cleanupFailed }
      return
    }
    let cleanupNow = lifecycle.requestStop()
    publication?.stop()
    if cleanupNow {
      await terminate(resources: resources)
      if cleanupFailed { throw NetworkTransportError.cleanupFailed }
      return
    }
    if lifecycle.phase != .terminated {
      await withCheckedContinuation { continuation in
        stopWaiters.append(continuation)
      }
    }
    if cleanupFailed { throw NetworkTransportError.cleanupFailed }
  }

  public func snapshot() -> TransportLifecycleSnapshot {
    TransportLifecycleSnapshot(
      phase: lifecycle.phase,
      activeChildren: childRegistry.count,
      bonjourPublished: publication?.isPublished == true,
      groupShutdown: groupShutdown
    )
  }

  public func lastUpgradeRejection() -> WebSocketUpgradeRejection? {
    rejectionRecorder.value
  }

  private func publicationWasRemoved(expectedID: UUID) async {
    guard publication?.id == expectedID, lifecycle.phase == .running else { return }
    _ = lifecycle.requestStop()
    await terminate(resources: resources)
  }

  private func terminate(resources: Resources?) async {
    guard !cleanupInProgress else { return }
    cleanupInProgress = true
    _ = lifecycle.requestStop()
    publication?.stop()
    publication = nil
    resources?.listener.serviceRegistrationUpdateHandler = nil
    resources?.listener.service = nil

    var failed = cleanupFailed
    let children = childRegistry.beginStopping()
    for child in children {
      do {
        try await child.close()
      } catch {
        failed = true
      }
    }
    if let serverChannel = resources?.serverChannel {
      do {
        try await serverChannel.close()
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
    if childRegistry.count != 0 {
      failed = true
    }
    cleanupFailed = failed
    self.resources = nil
    lifecycle.terminate()
    cleanupInProgress = false
    let waiters = stopWaiters
    stopWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }

  private func makeTLSOptions(certificate: TLSCertificateMaterial) throws -> NWProtocolTLS.Options {
    let tlsOptions = NWProtocolTLS.Options()
    let securityOptions = tlsOptions.securityProtocolOptions
    guard let identity = sec_identity_create(certificate.secIdentity) else {
      throw NetworkTransportError.identityBridgeFailed
    }
    sec_protocol_options_set_local_identity(securityOptions, identity)
    sec_protocol_options_set_min_tls_protocol_version(securityOptions, .TLSv13)
    sec_protocol_options_set_max_tls_protocol_version(securityOptions, .TLSv13)
    sec_protocol_options_append_tls_ciphersuite(securityOptions, .AES_128_GCM_SHA256)
    sec_protocol_options_set_tls_tickets_enabled(securityOptions, false)
    sec_protocol_options_set_tls_resumption_enabled(securityOptions, false)
    sec_protocol_options_set_tls_false_start_enabled(securityOptions, false)
    sec_protocol_options_set_tls_is_fallback_attempt(securityOptions, false)
    sec_protocol_options_set_peer_authentication_required(securityOptions, false)
    sec_protocol_options_add_tls_application_protocol(securityOptions, "http/1.1")
    return tlsOptions
  }
}
