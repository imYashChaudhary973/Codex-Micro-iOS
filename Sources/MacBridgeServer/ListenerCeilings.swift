import CompanionProtocol
import Foundation

/// Monotonic nanosecond time seam.
///
/// Every ceiling in this file is measured on this seam, never on the wall
/// clock, so a backwards clock step can neither widen a rate window nor
/// extend a deadline, and deterministic tests drive time explicitly.
public enum ListenerMonotonicClock {
  /// The system monotonic source.
  public static let system: @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
}

/// The resource ceilings the listener enforces (ADR §9 "ceilings for Step
/// 2.7").
///
/// The defaults are exactly the ADR values. A configuration may **tighten**
/// any value; ``validated()`` rejects one that exceeds the ADR ceiling, so a
/// misconfiguration cannot silently widen the untrusted-input bounds.
public struct ListenerCeilings: Equatable, Sendable {
  /// TLS + HTTP upgrade completion deadline, in seconds from accept.
  public let upgradeDeadlineSeconds: Int
  /// Authentication deadline, in seconds from upgrade completion.
  public let authenticationDeadlineSeconds: Int
  /// Global concurrent-connection ceiling.
  public let maxConcurrentConnections: Int
  /// Concurrent unauthenticated-connection ceiling.
  public let maxUnauthenticatedConnections: Int
  /// Per-source new connections per minute.
  public let maxNewConnectionsPerSourcePerMinute: Int
  /// Per-source pairing attempts per minute.
  public let maxPairingAttemptsPerSourcePerMinute: Int
  /// Per-connection inbound messages per second.
  public let maxInboundMessagesPerSecond: Int
  /// Per-connection inbound bytes per second.
  public let maxInboundBytesPerSecond: Int
  /// Outbound queue ceiling in frames.
  public let maxOutboundQueueFrames: Int
  /// Outbound queue ceiling in bytes.
  public let maxOutboundQueueBytes: Int
  /// Maximum seconds a connection may stay non-writable before closing.
  public let maxNonWritableSeconds: Int
  /// Server ping cadence in seconds.
  public let pingCadenceSeconds: Int
  /// Matching-pong deadline in seconds.
  public let pongDeadlineSeconds: Int
  /// Post-upgrade application idle expiry in seconds.
  public let idleExpirySeconds: Int
  /// Maximum raw bytes one connection may send before the HTTP upgrade
  /// completes.
  ///
  /// This is a Step 2.7 **tightening** with no ADR §9 counterpart: NIO only
  /// consults the upgrade policy once an `Upgrade` header is present, so a
  /// plain `GET`/`POST` never reaches ``ListenerUpgradePolicy`` and would
  /// otherwise be free to stream a body for the whole upgrade deadline. The
  /// default is twice the header ceiling, which no legitimate upgrade
  /// request approaches.
  public let maxPreUpgradeBytes: Int

  /// The absolute ceiling on pre-upgrade bytes. A configuration may tighten
  /// below it and never exceed it.
  public static let preUpgradeByteCeiling = 2 * SecureTransportLimits.maxHeaderTotalBytes

  /// Creates a ceiling set; the defaults are the ADR §9 values.
  public init(
    upgradeDeadlineSeconds: Int = SecureTransportLimits.upgradeDeadlineSeconds,
    authenticationDeadlineSeconds: Int = SecureTransportLimits.authenticationDeadlineSeconds,
    maxConcurrentConnections: Int = SecureTransportLimits.maxConcurrentConnections,
    maxUnauthenticatedConnections: Int = SecureTransportLimits.maxUnauthenticatedConnections,
    maxNewConnectionsPerSourcePerMinute: Int = SecureTransportLimits
      .maxNewConnectionsPerSourcePerMinute,
    maxPairingAttemptsPerSourcePerMinute: Int = SecureTransportLimits
      .maxPairingAttemptsPerSourcePerMinute,
    maxInboundMessagesPerSecond: Int = SecureTransportLimits.maxInboundMessagesPerSecond,
    maxInboundBytesPerSecond: Int = SecureTransportLimits.maxInboundBytesPerSecond,
    maxOutboundQueueFrames: Int = SecureTransportLimits.maxOutboundQueueFrames,
    maxOutboundQueueBytes: Int = SecureTransportLimits.maxOutboundQueueBytes,
    maxNonWritableSeconds: Int = SecureTransportLimits.maxNonWritableSeconds,
    pingCadenceSeconds: Int = SecureTransportLimits.pingCadenceSeconds,
    pongDeadlineSeconds: Int = SecureTransportLimits.pongDeadlineSeconds,
    idleExpirySeconds: Int = SecureTransportLimits.idleExpirySeconds,
    maxPreUpgradeBytes: Int = ListenerCeilings.preUpgradeByteCeiling
  ) {
    self.maxPreUpgradeBytes = maxPreUpgradeBytes
    self.upgradeDeadlineSeconds = upgradeDeadlineSeconds
    self.authenticationDeadlineSeconds = authenticationDeadlineSeconds
    self.maxConcurrentConnections = maxConcurrentConnections
    self.maxUnauthenticatedConnections = maxUnauthenticatedConnections
    self.maxNewConnectionsPerSourcePerMinute = maxNewConnectionsPerSourcePerMinute
    self.maxPairingAttemptsPerSourcePerMinute = maxPairingAttemptsPerSourcePerMinute
    self.maxInboundMessagesPerSecond = maxInboundMessagesPerSecond
    self.maxInboundBytesPerSecond = maxInboundBytesPerSecond
    self.maxOutboundQueueFrames = maxOutboundQueueFrames
    self.maxOutboundQueueBytes = maxOutboundQueueBytes
    self.maxNonWritableSeconds = maxNonWritableSeconds
    self.pingCadenceSeconds = pingCadenceSeconds
    self.pongDeadlineSeconds = pongDeadlineSeconds
    self.idleExpirySeconds = idleExpirySeconds
  }

  /// Returns `self` when every value is positive and no value exceeds the
  /// ADR §9 ceiling; throws ``ListenerStartupFailure/ceilingsExceedADR``
  /// otherwise. Startup calls this before anything binds.
  public func validated() throws -> ListenerCeilings {
    let bounds: [(Int, Int)] = [
      (upgradeDeadlineSeconds, SecureTransportLimits.upgradeDeadlineSeconds),
      (authenticationDeadlineSeconds, SecureTransportLimits.authenticationDeadlineSeconds),
      (maxConcurrentConnections, SecureTransportLimits.maxConcurrentConnections),
      (maxUnauthenticatedConnections, SecureTransportLimits.maxUnauthenticatedConnections),
      (
        maxNewConnectionsPerSourcePerMinute,
        SecureTransportLimits.maxNewConnectionsPerSourcePerMinute
      ),
      (
        maxPairingAttemptsPerSourcePerMinute,
        SecureTransportLimits.maxPairingAttemptsPerSourcePerMinute
      ),
      (maxInboundMessagesPerSecond, SecureTransportLimits.maxInboundMessagesPerSecond),
      (maxInboundBytesPerSecond, SecureTransportLimits.maxInboundBytesPerSecond),
      (maxOutboundQueueFrames, SecureTransportLimits.maxOutboundQueueFrames),
      (maxOutboundQueueBytes, SecureTransportLimits.maxOutboundQueueBytes),
      (maxNonWritableSeconds, SecureTransportLimits.maxNonWritableSeconds),
      (pingCadenceSeconds, SecureTransportLimits.pingCadenceSeconds),
      (pongDeadlineSeconds, SecureTransportLimits.pongDeadlineSeconds),
      (idleExpirySeconds, SecureTransportLimits.idleExpirySeconds),
      (maxPreUpgradeBytes, Self.preUpgradeByteCeiling),
    ]
    for (value, ceiling) in bounds where value <= 0 || value > ceiling {
      throw ListenerStartupFailure.ceilingsExceedADR
    }
    guard maxUnauthenticatedConnections <= maxConcurrentConnections else {
      throw ListenerStartupFailure.ceilingsExceedADR
    }
    // Consistency: the server ping cadence must stay outside the window an
    // unauthenticated peer can occupy. The keep-alive handler additionally
    // starts the cadence only after authentication, so this is defence in
    // depth against a tightened cadence reintroducing server-originated
    // traffic on a connection that never authenticated.
    guard pingCadenceSeconds > authenticationDeadlineSeconds else {
      throw ListenerStartupFailure.ceilingsInconsistent
    }
    // Consistency: idle expiry must outlast one full ping/pong round so a
    // live connection is never expired between two cadence ticks.
    guard idleExpirySeconds > pingCadenceSeconds + pongDeadlineSeconds else {
      throw ListenerStartupFailure.ceilingsInconsistent
    }
    // Consistency: the pre-upgrade byte budget must admit a maximal
    // legitimate upgrade request.
    guard maxPreUpgradeBytes >= SecureTransportLimits.maxHeaderTotalBytes else {
      throw ListenerStartupFailure.ceilingsInconsistent
    }
    return self
  }
}

/// Closed admission-rejection vocabulary. The peer is closed without a
/// reason body; the code exists for counts and tests only.
public enum ListenerAdmissionRejection: String, Error, Equatable, CaseIterable, Sendable {
  /// The global concurrent-connection ceiling is reached.
  case globalCapacity
  /// The concurrent unauthenticated-connection ceiling is reached.
  case unauthenticatedCapacity
  /// The source exceeded its new-connections-per-minute ceiling.
  case sourceConnectionRate
  /// The source exceeded its pairing-attempts-per-minute ceiling.
  case sourcePairingRate
  /// The listener is no longer accepting connections.
  case notAccepting
}

/// Opaque per-source key.
///
/// It wraps the peer's numeric address only — never a port, hostname, or
/// any other peer-supplied byte — and exists solely as a dictionary key.
/// It is deliberately not `CustomStringConvertible`: the wrapped value must
/// never reach a log line.
public struct ListenerSourceKey: Hashable, Sendable {
  let value: String

  /// Creates a key from a peer's numeric address.
  public init(numericAddress: String) {
    self.value = numericAddress
  }
}

/// A live admission grant. Releasing it is idempotent and happens exactly
/// once per connection, on channel close.
public final class ListenerConnectionTicket: @unchecked Sendable {
  private let lock = NSLock()
  private weak var controller: ListenerAdmissionController?
  private var released = false
  private var authenticated = false
  let source: ListenerSourceKey

  init(controller: ListenerAdmissionController, source: ListenerSourceKey) {
    self.controller = controller
    self.source = source
  }

  /// Whether this connection has authenticated. Unauthenticated tickets
  /// occupy the unauthenticated ceiling.
  public var isAuthenticated: Bool {
    lock.withLock { authenticated }
  }

  /// Promotes the connection out of the unauthenticated ceiling. Repeated
  /// calls are ignored.
  public func markAuthenticated() {
    let promote: Bool = lock.withLock {
      guard !authenticated, !released else { return false }
      authenticated = true
      return true
    }
    if promote {
      controller?.promote()
    }
  }

  /// Releases the connection's slots. Repeated calls are ignored.
  public func release() {
    let state: (Bool, Bool) = lock.withLock {
      guard !released else { return (false, false) }
      released = true
      return (true, authenticated)
    }
    guard state.0 else { return }
    controller?.release(wasAuthenticated: state.1)
    controller = nil
  }

  deinit {
    release()
  }
}

/// App-level connection admission (ADR §9: NIOTS has no native connection
/// cap, so the cap is enforced here).
///
/// It enforces the global and unauthenticated concurrency ceilings, the
/// per-source new-connections-per-minute ceiling, and two per-source
/// handshake-message ceilings, all on an injected monotonic clock.
///
/// **Memory bound.** Admission runs at accept, before TLS, so an attacker
/// cycling source addresses — trivial with IPv6 privacy addresses — would
/// otherwise add a permanent map entry per connection while the per-source
/// ceiling never engaged, because no address is ever reused. The map is
/// therefore pruned on the production admission paths themselves (not only
/// by an external caller) once it passes a soft threshold, and is hard
/// capped: past the cap the entries whose most recent sample is oldest are
/// evicted first. Per-source sample arrays are separately bounded by their
/// own ceilings.
public final class ListenerAdmissionController: @unchecked Sendable {
  private struct SourceWindows {
    var connections: [UInt64] = []
    var pairingAttempts: [UInt64] = []
    var authenticationAttempts: [UInt64] = []

    var isEmpty: Bool {
      connections.isEmpty && pairingAttempts.isEmpty && authenticationAttempts.isEmpty
    }

    var mostRecentSample: UInt64 {
      max(connections.last ?? 0, max(pairingAttempts.last ?? 0, authenticationAttempts.last ?? 0))
    }
  }

  private static let minuteNanoseconds: UInt64 = 60 * 1_000_000_000
  /// Pruning starts once the map passes this size.
  static let sourcePruneThreshold = 64
  /// The map never exceeds this size; past it the least recently active
  /// entries are evicted.
  static let sourceHardCap = 512

  private let lock = NSLock()
  private let ceilings: ListenerCeilings
  private let now: @Sendable () -> UInt64
  private var accepting = true
  private var activeConnections = 0
  private var activeUnauthenticated = 0
  private var sources: [ListenerSourceKey: SourceWindows] = [:]

  /// Creates a controller.
  ///
  /// - Parameters:
  ///   - ceilings: Already-validated ceilings.
  ///   - now: Monotonic nanosecond seam; tests inject a controlled source.
  public init(
    ceilings: ListenerCeilings,
    now: @escaping @Sendable () -> UInt64 = ListenerMonotonicClock.system
  ) {
    self.ceilings = ceilings
    self.now = now
  }

  /// Admits one new connection from `source`, or returns the closed
  /// rejection code. A rejection consumes no slot and records no sample, so
  /// a rejected flood cannot itself extend the source's window.
  public func admit(
    source: ListenerSourceKey
  ) -> Result<ListenerConnectionTicket, ListenerAdmissionRejection> {
    let instant = now()
    return lock.withLock {
      guard accepting else { return .failure(.notAccepting) }
      pruneLocked(at: instant)
      guard activeConnections < ceilings.maxConcurrentConnections else {
        return .failure(.globalCapacity)
      }
      guard activeUnauthenticated < ceilings.maxUnauthenticatedConnections else {
        return .failure(.unauthenticatedCapacity)
      }
      var windows = sources[source] ?? SourceWindows()
      windows.connections = Self.pruned(windows.connections, at: instant)
      guard windows.connections.count < ceilings.maxNewConnectionsPerSourcePerMinute else {
        sources[source] = windows
        return .failure(.sourceConnectionRate)
      }
      windows.connections.append(instant)
      sources[source] = windows
      activeConnections += 1
      activeUnauthenticated += 1
      return .success(ListenerConnectionTicket(controller: self, source: source))
    }
  }

  /// Records one handshake message from `source` against its per-source
  /// ceiling, returning `false` when that ceiling is already reached.
  ///
  /// Two windows exist because the two flows have different costs and
  /// different legitimate frequencies:
  ///
  /// - Pairing (`pairingRequest`, `pairingConfirmation`) uses the ADR §9
  ///   per-source pairing ceiling. Pairing is a rare, human-driven action
  ///   inside a five-minute window.
  /// - Authentication (`sessionAuthRequest`, `sessionAuthConfirmation`)
  ///   uses the per-source **connection** ceiling, because each
  ///   authentication needs a connection anyway, so it introduces no number
  ///   the ADR does not already fix.
  ///
  /// Without this, only `pairingRequest` was counted and a source could
  /// spend a full authentication deadline issuing signature verifications on
  /// every unauthenticated slot. A refused message is not recorded.
  public func admitHandshakeMessage(
    _ kind: ListenerHandshakeKind,
    source: ListenerSourceKey
  ) -> Bool {
    guard let window = kind.sourceWindow else { return true }
    let instant = now()
    return lock.withLock {
      pruneLocked(at: instant)
      var windows = sources[source] ?? SourceWindows()
      defer { sources[source] = windows }
      switch window {
      case .pairing:
        windows.pairingAttempts = Self.pruned(windows.pairingAttempts, at: instant)
        guard windows.pairingAttempts.count < ceilings.maxPairingAttemptsPerSourcePerMinute
        else {
          return false
        }
        windows.pairingAttempts.append(instant)
      case .authentication:
        windows.authenticationAttempts = Self.pruned(
          windows.authenticationAttempts, at: instant)
        guard
          windows.authenticationAttempts.count < ceilings.maxNewConnectionsPerSourcePerMinute
        else {
          return false
        }
        windows.authenticationAttempts.append(instant)
      }
      return true
    }
  }

  /// Stops admitting new connections. Teardown calls this before closing
  /// tracked children.
  public func stopAccepting() {
    lock.withLock { accepting = false }
  }

  /// Live counts for teardown assertions and redacted metrics.
  public var counts: (total: Int, unauthenticated: Int) {
    lock.withLock { (activeConnections, activeUnauthenticated) }
  }

  /// The number of per-source windows currently retained. Bounded by
  /// ``sourceHardCap``; exposed so a test can prove the map cannot grow
  /// without bound.
  public var trackedSourceCount: Int {
    lock.withLock { sources.count }
  }

  /// Drops per-source windows with no samples inside the current minute.
  ///
  /// The admission paths call this themselves once the map passes the soft
  /// threshold; this entry point exists for callers that want to reclaim
  /// eagerly (for example at teardown).
  public func pruneIdleSources() {
    let instant = now()
    lock.withLock { pruneLocked(at: instant, force: true) }
  }

  private func pruneLocked(at instant: UInt64, force: Bool = false) {
    guard force || sources.count >= Self.sourcePruneThreshold else { return }
    for (key, windows) in sources {
      var pruned = windows
      pruned.connections = Self.pruned(windows.connections, at: instant)
      pruned.pairingAttempts = Self.pruned(windows.pairingAttempts, at: instant)
      pruned.authenticationAttempts = Self.pruned(windows.authenticationAttempts, at: instant)
      if pruned.isEmpty {
        sources.removeValue(forKey: key)
      } else {
        sources[key] = pruned
      }
    }
    guard sources.count > Self.sourceHardCap else { return }
    // Hard cap: evict least recently active sources first. Evicting only
    // resets a limiter that the global and unauthenticated concurrency caps
    // already bound, so this cannot widen the admission surface.
    let ordered = sources.sorted { $0.value.mostRecentSample < $1.value.mostRecentSample }
    for entry in ordered.prefix(sources.count - Self.sourceHardCap) {
      sources.removeValue(forKey: entry.key)
    }
  }

  fileprivate func promote() {
    lock.withLock {
      guard activeUnauthenticated > 0 else { return }
      activeUnauthenticated -= 1
    }
  }

  fileprivate func release(wasAuthenticated: Bool) {
    lock.withLock {
      if activeConnections > 0 { activeConnections -= 1 }
      if !wasAuthenticated, activeUnauthenticated > 0 { activeUnauthenticated -= 1 }
    }
  }

  private static func pruned(_ samples: [UInt64], at instant: UInt64) -> [UInt64] {
    let cutoff = instant >= minuteNanoseconds ? instant - minuteNanoseconds : 0
    return samples.filter { $0 > cutoff }
  }
}

/// Per-connection inbound message and byte rate meter (ADR §9: 32 messages
/// per second and 1 MiB per second).
///
/// Both windows slide over exactly one second on the injected monotonic
/// seam. Exceeding either closes the connection; the meter itself only
/// reports.
public final class ListenerInboundRateMeter: @unchecked Sendable {
  private static let secondNanoseconds: UInt64 = 1_000_000_000

  private let lock = NSLock()
  private let maxMessages: Int
  private let maxBytes: Int
  private let now: @Sendable () -> UInt64
  private var samples: [(instant: UInt64, bytes: Int)] = []

  /// Creates a meter bound to the ADR ceilings and a monotonic seam.
  public init(
    maxMessagesPerSecond: Int,
    maxBytesPerSecond: Int,
    now: @escaping @Sendable () -> UInt64 = ListenerMonotonicClock.system
  ) {
    precondition(maxMessagesPerSecond > 0)
    precondition(maxBytesPerSecond > 0)
    self.maxMessages = maxMessagesPerSecond
    self.maxBytes = maxBytesPerSecond
    self.now = now
  }

  /// Records one inbound message of `bytes` and reports whether both
  /// windows stay inside their ceilings. A refused message is still
  /// recorded: it consumed inbound capacity.
  public func admit(bytes: Int) -> Bool {
    let instant = now()
    return lock.withLock {
      let cutoff = instant >= Self.secondNanoseconds ? instant - Self.secondNanoseconds : 0
      samples.removeAll { $0.instant <= cutoff }
      samples.append((instant, bytes))
      let totalBytes = samples.reduce(0) { $0 + $1.bytes }
      return samples.count <= maxMessages && totalBytes <= maxBytes
    }
  }
}
