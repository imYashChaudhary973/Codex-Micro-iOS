import Foundation

/// Closed listener lifecycle failure vocabulary (ADR §14).
public enum ListenerError: Error, Equatable, Sendable {
  /// A second start was requested on a listener that already started.
  case alreadyStarted
  /// Teardown could not complete every step; residual state may exist.
  case cleanupFailed
  /// The `SecIdentity` could not be bridged into Network.framework TLS.
  case identityBridgeFailed
  /// The bind target failed revalidation at startup.
  case invalidBinding
  /// The bound channel exposed no `NWListener`.
  case listenerUnavailable
  /// The bound channel exposed no local port.
  case portUnavailable
  /// A stop was requested while starting; the listener terminated instead.
  case startCancelled
  /// The listener is terminated and cannot be restarted (one-shot).
  case terminated
  /// A startup prerequisite denied the listener (fail closed).
  case startupDenied(ListenerStartupFailure)
  /// The bounded outbound queue overflowed; the write was refused and the
  /// connection closed (ADR §9 slow-consumer policy).
  case outboundQueueExceeded
  /// The peer sent more bytes before the HTTP upgrade than the pre-upgrade
  /// budget allows.
  case preUpgradeBudgetExceeded
}
/// The listener's one-shot lifecycle phases (ADR §14).
///
/// `publishing` exists in the vocabulary because ADR §14 fixes the shape of
/// the state machine, but **Step 2.7 adds no production Bonjour in any
/// form**; nothing in this step ever enters it. Step 2.13 owns advertisement.
public enum ListenerPhase: String, Equatable, Sendable {
  /// Created and never started.
  case idle
  /// Startup in progress.
  case starting
  /// Bound and accepting.
  case running
  /// Reserved for Step 2.13 advertisement; unreachable in Step 2.7.
  case publishing
  /// Teardown in progress.
  case stopping
  /// Terminal. A terminated listener never restarts.
  case terminated
}

/// The explicit one-shot transition table (ADR §14).
///
/// There is no path back to `idle` or `running` from `terminated`, and a
/// stop requested during startup makes the startup fail rather than
/// producing a half-open listener.
public struct ListenerLifecycleStateMachine: Equatable, Sendable {
  /// The current phase.
  public private(set) var phase: ListenerPhase = .idle
  /// Whether a stop has been requested at any point.
  public private(set) var stopRequested = false

  /// Creates a machine in `idle`.
  public init() {}

  /// Enters `starting`, or throws when the listener already started or
  /// terminated.
  public mutating func beginStart() throws {
    guard phase == .idle else {
      throw phase == .terminated ? ListenerError.terminated : ListenerError.alreadyStarted
    }
    phase = .starting
  }

  /// Completes startup. Returns `false` — and moves to `stopping` — when a
  /// stop was requested while starting.
  public mutating func completeStart() -> Bool {
    guard phase == .starting, !stopRequested else {
      phase = .stopping
      return false
    }
    phase = .running
    return true
  }

  /// Requests a stop. Returns `true` when the caller must run teardown now;
  /// `false` when an in-flight transition will run it.
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

  /// Enters the terminal phase.
  public mutating func terminate() {
    stopRequested = true
    phase = .terminated
  }
}

/// A sanitized listener state snapshot.
///
/// It exposes only phase, counts, and booleans — never an address, port,
/// device, or peer value — so it is safe to assert on in tests and safe to
/// surface in redacted diagnostics.
public struct ListenerSnapshot: Equatable, Sendable {
  /// The current phase.
  public let phase: ListenerPhase
  /// Tracked child connections still registered.
  public let activeChildren: Int
  /// Tracked child connections that have authenticated.
  public let authenticatedChildren: Int
  /// Always `false` in Step 2.7: this step publishes no Bonjour service.
  public let bonjourPublished: Bool
  /// Whether the event-loop group finished shutting down.
  public let groupShutdown: Bool

  /// Creates a snapshot.
  public init(
    phase: ListenerPhase,
    activeChildren: Int,
    authenticatedChildren: Int,
    bonjourPublished: Bool,
    groupShutdown: Bool
  ) {
    self.phase = phase
    self.activeChildren = activeChildren
    self.authenticatedChildren = authenticatedChildren
    self.bonjourPublished = bonjourPublished
    self.groupShutdown = groupShutdown
  }
}

/// The bound endpoint a successful start returns.
///
/// The host and port are the values the deterministic loopback client needs
/// to connect; neither is ever logged.
public struct ListenerEndpoint: Equatable, Sendable {
  /// The numeric bind address.
  public let host: String
  /// The bound port.
  public let port: Int
  /// The SHA-256 SPKI fingerprint a client must pin.
  public let spkiFingerprint: Data

  /// Creates an endpoint.
  public init(host: String, port: Int, spkiFingerprint: Data) {
    self.host = host
    self.port = port
    self.spkiFingerprint = spkiFingerprint
  }
}
