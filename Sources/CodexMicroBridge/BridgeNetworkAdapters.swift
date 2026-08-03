import CompanionCrypto
import CompanionProtocol
import Foundation
import MacBridgeCore
import MacBridgeServer

/// The adapters that join the three targets Phase 2 deliberately kept apart.
///
/// `MacBridgeServer` owns the transport and imports no core; `MacBridgeCore`
/// owns authority and imports no crypto; `CompanionCrypto` owns the state
/// machines and imports neither. Every seam between them is a protocol, and
/// this file is the one place those protocols are satisfied — which is why
/// the executor-bypass rule holds by construction rather than by discipline:
/// there is exactly one file to review for it, and it is this one.
///
/// Nothing here makes an authorization decision. Each adapter translates a
/// question from one module into a call on another and returns the answer
/// unchanged.

// MARK: - Grant authority → session authority

/// Answers the session coordinator's authority reads from the Mac-stored
/// grant authority.
///
/// The coordinator needs one read that returns the device's stored key, the
/// three counters a session is admitted under, liveness, and the grant's
/// remaining lifetime **as a duration**. The duration matters: the
/// coordinator converts it once, at authentication, onto its monotonic seam,
/// so no later wall-clock movement can extend a live session.
public struct GrantAuthoritySessionAuthority: SessionAuthorityProviding {
  private let authority: DeviceGrantAuthority
  private let clock: @Sendable () -> UInt64

  public init(
    authority: DeviceGrantAuthority,
    clock: @escaping @Sendable () -> UInt64 = {
      UInt64(max(0, Date().timeIntervalSince1970.rounded(.down)))
    }
  ) {
    self.authority = authority
    self.clock = clock
  }

  public func authoritySnapshot(deviceID: UUID) async throws -> SessionAuthoritySnapshot? {
    let hostGeneration: UInt64
    let commitSequence: UInt64
    do {
      hostGeneration = try await authority.currentHostGeneration()
      commitSequence = try await authority.currentAuthoritySequence()
    } catch {
      // An unavailable authority must deny authentication outright rather
      // than fall back to anything (plan §2 invariant 15). Throwing is what
      // the seam defines as "unavailable"; returning nil would read as
      // "unknown device", which is a different and weaker answer.
      throw error
    }

    let record: AuthoritativeDeviceGrant
    do {
      record = try await authority.authoritativeGrant(deviceID: deviceID)
    } catch DeviceGrantAuthorityError.deviceUnknown {
      return nil
    } catch DeviceGrantAuthorityError.deviceRevoked {
      return try await tombstoned(deviceID: deviceID, liveness: .revoked)
    } catch DeviceGrantAuthorityError.deviceExpired {
      return try await tombstoned(deviceID: deviceID, liveness: .expired)
    }

    return try SessionAuthoritySnapshot(
      deviceID: record.deviceID,
      devicePublicKeyX963: record.devicePublicKey,
      grantRevision: record.grantRevision,
      authorizedViewEpoch: record.authorizedViewEpoch,
      hostGeneration: hostGeneration,
      authorityCommitSequence: commitSequence,
      liveness: .live,
      remainingLifetimeSeconds: Self.remainingLifetime(record, now: clock()),
      grantExpiresAtEpochSeconds: record.expiresAtEpochSeconds
    )
  }

  /// A revoked or expired device still needs a snapshot carrying its closed
  /// liveness, so the coordinator denies with the right reason rather than
  /// with "unknown device". The record is read through the administration
  /// view because the live accessor refuses a tombstoned grant by design.
  private func tombstoned(
    deviceID: UUID,
    liveness: SessionAuthorityLiveness
  ) async throws -> SessionAuthoritySnapshot? {
    let snapshot = try await authority.macAdministrationSnapshot()
    guard let record = snapshot.grants.first(where: { $0.deviceID == deviceID }) else {
      return nil
    }
    return try SessionAuthoritySnapshot(
      deviceID: record.deviceID,
      devicePublicKeyX963: record.devicePublicKey,
      grantRevision: record.grantRevision,
      authorizedViewEpoch: record.authorizedViewEpoch,
      hostGeneration: snapshot.hostGeneration,
      authorityCommitSequence: snapshot.authoritySequence,
      liveness: liveness,
      remainingLifetimeSeconds: 0,
      grantExpiresAtEpochSeconds: record.expiresAtEpochSeconds
    )
  }

  /// Seconds of grant life left, or `nil` when the grant never expires. A
  /// grant already past its instant reports `0` rather than underflowing.
  static func remainingLifetime(_ record: AuthoritativeDeviceGrant, now: UInt64) -> UInt64? {
    guard let expiresAt = record.expiresAtEpochSeconds else { return nil }
    return expiresAt > now ? expiresAt - now : 0
  }
}

// MARK: - Session coordinator → gateway session verifier

/// Confirms to the command gateway that a session is still the device's
/// current, valid one.
///
/// The gateway cannot import `CompanionCrypto`, so it asks through this
/// adapter. `validate` already re-reads the Mac authority and re-checks the
/// registry, so a session whose authorization changed is refused here before
/// any command is claimed.
public struct SessionCoordinatorVerifier: NetworkSessionVerifying {
  private let coordinator: SessionCoordinator

  public init(coordinator: SessionCoordinator) {
    self.coordinator = coordinator
  }

  public func isCurrentSession(deviceID: UUID, sessionID: UUID) async -> Bool {
    // The connection ID is not part of the question: the gateway asks whether
    // *this device* still holds *this session*, and the registry keys on
    // exactly that pair. A zero connection ID never matches a stored record
    // by accident because `requireCurrent` compares the session ID.
    let identity = AuthenticatedSessionIdentity(
      sessionID: sessionID,
      connectionID: sessionID,
      deviceID: deviceID
    )
    guard let record = try? await coordinator.validate(identity) else { return false }
    return record.identity.sessionID == sessionID && record.identity.deviceID == deviceID
  }
}

// MARK: - Observation broker → transport

/// Hands the listener already-filtered observation batches from the broker.
///
/// Every value crossing this adapter has already been filtered against the
/// device's current Mac-stored scope. The adapter translates the broker's
/// closed failures into the transport's closed refusals and adds no policy
/// of its own.
public struct BrokerObservationHandler: ListenerObservationHandling {
  private let broker: DeviceObservationBroker

  public init(broker: DeviceObservationBroker) {
    self.broker = broker
  }

  public func subscribe(
    deviceID: UUID,
    subscriptionID: UUID,
    resumeCursor: ReplayCursorEnvelope?
  ) async throws -> ListenerObservationBatch {
    do {
      let batch = try await broker.subscribe(
        deviceID: deviceID, subscriptionID: subscriptionID, resumeCursor: resumeCursor)
      return Self.transportBatch(batch)
    } catch {
      throw Self.refusal(for: error)
    }
  }

  public func nextBatch(deviceID: UUID) async throws -> ListenerObservationBatch? {
    do {
      guard let batch = try await broker.nextBatch(deviceID: deviceID) else { return nil }
      return Self.transportBatch(batch)
    } catch {
      throw Self.refusal(for: error)
    }
  }

  public func acknowledge(
    deviceID: UUID,
    subscriptionID: UUID,
    cursor: ReplayCursorEnvelope
  ) async throws {
    do {
      try await broker.acknowledge(
        deviceID: deviceID, subscriptionID: subscriptionID, cursor: cursor)
    } catch {
      throw Self.refusal(for: error)
    }
  }

  public func release(deviceID: UUID) async {
    await broker.unsubscribe(deviceID: deviceID)
  }

  static func transportBatch(_ batch: AuthorizedObservationBatch) -> ListenerObservationBatch {
    switch batch {
    case .snapshot(let snapshot, let cursor):
      return ListenerObservationBatch(payload: .snapshot(snapshot), cursor: cursor)
    case .events(let events, let cursor):
      return ListenerObservationBatch(payload: .events(events), cursor: cursor)
    }
  }

  /// Maps the broker's closed failures onto the transport's closed refusals.
  static func refusal(for error: any Error) -> ListenerObservationRefusal {
    guard let failure = error as? ObservationSubscriptionError else { return .protocolViolation }
    switch failure {
    case .notObservable: return .notAuthorized
    case .authorityUnavailable: return .authorityUnavailable
    case .cursorRejected: return .cursorRejected
    case .unknownSubscription, .acknowledgementOutOfOrder, .projectionFailed:
      return .protocolViolation
    }
  }
}

// MARK: - Command gateway → transport

/// Hands the listener the gateway's closed command results.
///
/// This is the only path from a network message to a semantic mutation. The
/// adapter passes the authenticated identity through untouched and never
/// inspects the command.
public struct GatewayCommandHandler: ListenerCommandHandling {
  private let gateway: NetworkCommandGateway

  public init(gateway: NetworkCommandGateway) {
    self.gateway = gateway
  }

  public func execute(
    command: ClientCommand,
    deviceID: UUID,
    sessionID: UUID
  ) async -> ListenerCommandOutcome {
    let outcome = await gateway.execute(
      command: command,
      context: NetworkCommandContext(deviceID: deviceID, sessionID: sessionID)
    )
    return Self.transportOutcome(outcome)
  }

  static func transportOutcome(_ outcome: NetworkCommandOutcome) -> ListenerCommandOutcome {
    switch outcome {
    case .completed, .replayed: return .completed
    case .denied(let reason): return .denied(reason)
    case .outcomeUnknown: return .outcomeUnknown
    case .failed: return .failed
    }
  }
}
