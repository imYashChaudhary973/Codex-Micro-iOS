import CompanionProtocol
import Foundation
import MacBridgeCore
import MacBridgeServer

/// The user-facing LAN state the Mac menu shows.
public enum BridgeLANState: Equatable, Sendable {
  /// Off. Nothing is bound and nothing is advertised.
  case disabled
  /// Enable is in progress.
  case enabling
  /// Bound, accepting, and advertised.
  case enabled(host: String, port: Int)
  /// Disable is in progress.
  case disabling
  /// The last enable attempt failed. Nothing is bound or advertised; the
  /// closed reason is what the menu shows.
  case failed(BridgeLANFailure)
}

/// Closed LAN-control failure vocabulary. Carries no endpoint, address,
/// device, or certificate value.
public enum BridgeLANFailure: String, Error, Equatable, CaseIterable, Sendable {
  /// A startup prerequisite refused: identity, grant authority, policy,
  /// network configuration, or Codex support.
  case startupDenied
  /// The listener bound but the advertisement could not be published, so the
  /// listener was rolled back.
  case advertisementFailed
  /// Teardown could not be confirmed complete.
  case shutdownIncomplete
  /// Enable was requested while already enabling or enabled.
  case alreadyRunning
}

/// Starts and stops one listener. A seam because the real listener binds a
/// socket, and the ordering rules below must be provable without one.
///
/// Each `start` returns a **fresh** listener: the hardened listener's
/// lifecycle is one-shot by design (ADR §14), so a stopped one never
/// restarts and enabling again must build another.
public protocol BridgeListenerControlling: Sendable {
  func start() async throws -> ListenerEndpoint
  func stop() async throws
}

/// The Mac's LAN enable/disable control (plan Step 2.13).
///
/// It owns exactly one thing: **the order of operations**, which is where
/// this feature's failure modes live.
///
/// - Enabling binds first and advertises second, so a device that discovers
///   the service can always reach it.
/// - An advertisement failure rolls the listener back, so the bridge is
///   reachable-and-advertised or neither — never advertised-but-broken, and
///   never silently unadvertised after the user asked for discovery.
/// - Disabling removes the advertisement first and closes second, because the
///   other order leaves a record pointing at a closed port for as long as
///   mDNS caches it.
/// - A failed enable leaves the state `failed`, not `enabled`: the menu never
///   claims the LAN is on when it is not.
public actor BridgeLANController {
  private let makeListener: @Sendable () -> any BridgeListenerControlling
  private let bonjour: ListenerBonjourCoordinator
  /// Builds a publisher for the listener that was just started.
  ///
  /// The record has to be applied to the `NWListener` the bind produced, so
  /// the publisher cannot exist before the listener does. Passing a factory
  /// keeps the ordering the controller already enforces — bind, then
  /// advertise, roll back if publication fails — while letting the publisher
  /// reach the thing it publishes on.
  private let makePublisher:
    @Sendable (any BridgeListenerControlling) -> (
      any ListenerBonjourPublishing
    )?
  private var listener: (any BridgeListenerControlling)?
  private var state: BridgeLANState = .disabled

  public init(
    makeListener: @escaping @Sendable () -> any BridgeListenerControlling,
    bonjour: ListenerBonjourCoordinator = ListenerBonjourCoordinator(),
    makePublisher:
      @escaping @Sendable (any BridgeListenerControlling) -> (
        any ListenerBonjourPublishing
      )? = { _ in nil }
  ) {
    self.makeListener = makeListener
    self.bonjour = bonjour
    self.makePublisher = makePublisher
  }

  /// The state the menu shows.
  public func currentState() -> BridgeLANState { state }

  /// Enables LAN access: bind, then advertise.
  @discardableResult
  public func enable() async throws -> ListenerEndpoint {
    switch state {
    case .enabling, .enabled, .disabling:
      throw BridgeLANFailure.alreadyRunning
    case .disabled, .failed:
      break
    }
    state = .enabling

    let listener = makeListener()
    let endpoint: ListenerEndpoint
    do {
      endpoint = try await listener.start()
    } catch {
      state = .failed(.startupDenied)
      throw BridgeLANFailure.startupDenied
    }
    self.listener = listener

    if let publisher = makePublisher(listener) {
      await bonjour.use(publisher)
    }
    do {
      try await bonjour.publishAfterReadiness(rollback: {
        // Roll the bind back before anyone can observe a failed publication
        // while the listener is still bound.
        try? await listener.stop()
      })
    } catch {
      self.listener = nil
      state = .failed(.advertisementFailed)
      throw BridgeLANFailure.advertisementFailed
    }

    state = .enabled(host: endpoint.host, port: endpoint.port)
    return endpoint
  }

  /// Disables LAN access: remove the advertisement, then close.
  ///
  /// Disabling an already-disabled bridge is a no-op rather than an error, so
  /// a menu that double-fires cannot produce a spurious failure.
  public func disable() async throws {
    switch state {
    case .disabled, .failed:
      return
    case .enabling, .disabling, .enabled:
      break
    }
    state = .disabling
    let listener = self.listener
    self.listener = nil

    var shutdownFailed = false
    do {
      try await bonjour.removeThenClose(closeListener: {
        do {
          try await listener?.stop()
        } catch {
          shutdownFailed = true
        }
      })
    } catch {
      // A removal that could not be confirmed still closed the listener; the
      // record may linger until mDNS expires it.
      state = .failed(.shutdownIncomplete)
      throw BridgeLANFailure.shutdownIncomplete
    }
    if shutdownFailed {
      state = .failed(.shutdownIncomplete)
      throw BridgeLANFailure.shutdownIncomplete
    }
    state = .disabled
  }

  /// Whether a record is currently advertised.
  public func isAdvertising() async -> Bool {
    await bonjour.isPublished
  }
}

/// What the transport must do after an authorization change committed.
///
/// The authorization-change coordinator decides and purges; something has to
/// act on its decision, and that something needs both the coordinator and the
/// connections. This is it.
public struct BridgeAuthorizationEnforcer: Sendable {
  /// Closes exactly one device's connections with a closed reason.
  public typealias CloseAction = @Sendable (UUID, SecureCloseReason) async -> Void

  private let close: CloseAction

  public init(close: @escaping CloseAction) {
    self.close = close
  }

  /// Applies one committed outcome.
  ///
  /// Both actions close the device's current connections: `reauthenticate`
  /// means the device keeps a grant and may immediately open a new session,
  /// `close` means it has none. Neither leaves the old session usable, which
  /// is what plan §2 invariant 11 requires.
  public func apply(_ outcome: AuthorizationChangeOutcome) async {
    switch outcome.connectionAction {
    case .close(let reason):
      await close(outcome.deviceID, reason)
    case .reauthenticate:
      await close(outcome.deviceID, .authorizationChanged)
    }
  }

  /// Applies a batch, such as a host-generation advance.
  public func apply(_ outcomes: [AuthorizationChangeOutcome]) async {
    for outcome in outcomes {
      await apply(outcome)
    }
  }
}
