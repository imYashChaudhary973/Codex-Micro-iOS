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

// MARK: - Secure Enclave identity → statement signers

/// Signs pairing transcripts and session statements with the Mac's
/// Enclave-backed `.host` key.
///
/// Both seams want the same thing — canonical bytes in, exactly 64 raw `r||s`
/// bytes out — and ``BridgeIdentity/signStatement(_:)`` is that operation with
/// the private key never leaving the Enclave (ADR §6).
///
/// **One key signs both, and that is safe rather than convenient.** Every
/// signed statement in this system is encoded through
/// `CanonicalStatementDomain`, whose separator leads the bytes: a pairing
/// transcript is `codex-micro/pairing-transcript/v1`, a session statement is
/// `codex-micro/session-auth-statement/v1`, a rotation statement is
/// `codex-micro/rotation-statement/v1`. A signature over one can never verify
/// as another, so re-using the host key across them is not a cross-protocol
/// exposure. Sharing a key without that property would be.
///
/// **The role is enforced, not assumed.** The `.tls` identity serves TLS and
/// must never sign a statement; `TLSRotationAuthority` already refuses a
/// non-`.host` signer for rotation, and this refuses one here, so the rule
/// holds at every place a statement is signed rather than at one of them.
public struct EnclaveHostStatementSigner: PairingTranscriptSigner, SessionStatementSigner {
  /// Raised when the identity handed in is not the host identity.
  public enum Failure: Error, Equatable, Sendable {
    case wrongIdentityRole(BridgeIdentityRole)
  }

  private let identity: BridgeIdentity

  /// Creates the signer, refusing any identity that is not `.host`.
  public init(identity: BridgeIdentity) throws {
    guard identity.role == .host else {
      throw Failure.wrongIdentityRole(identity.role)
    }
    self.identity = identity
  }

  /// The host public key the device verifies against. The pairing coordinator
  /// needs it alongside the signer, and reading it from the same identity is
  /// what stops a coordinator being built with a key that does not match the
  /// signature it will produce.
  public var hostPublicKeyX963: Data { identity.publicKeyX963 }

  public func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try identity.signStatement(canonicalBytes)
  }

  public func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    try identity.signStatement(canonicalBytes)
  }
}

// MARK: - Pairing proposal → stored grant

/// Turns a completed pairing into the Mac's authoritative grant.
///
/// Pairing itself stores nothing — `PairedDeviceProposal` is documented as
/// "the only successful pairing output: a proposal the Mac assembly turns into
/// a stored grant". This is that assembly step, and without it a successful
/// pairing produced a device the Mac had never heard of.
///
/// **The mapping is closed and cannot widen.** `PairedDeviceGrantIntent` has
/// exactly one constructible value, so pairing can only ever propose `observe`
/// with an empty project allowlist (plan §2 invariant 4). The capability
/// translation is a total `switch`, so adding an intent case fails to compile
/// here rather than silently falling through to something permissive, and the
/// action-profile ceiling is pinned to `.observe` rather than derived — a
/// freshly paired device can see nothing until the Mac user grants a project.
public struct PairingGrantRecorder: Sendable {
  private let authority: DeviceGrantAuthority

  public init(authority: DeviceGrantAuthority) {
    self.authority = authority
  }

  /// Records the proposal as a grant and returns the stored record.
  ///
  /// A duplicate device is the authority's decision, not this adapter's: it
  /// throws, and re-pairing an already-known device must go through explicit
  /// administration rather than silently overwriting a grant revision.
  @discardableResult
  public func record(_ proposal: PairedDeviceProposal) async throws -> AuthoritativeDeviceGrant {
    try await authority.addGrant(
      deviceID: proposal.deviceID,
      devicePublicKey: proposal.devicePublicKeyX963,
      capabilities: Self.capabilities(proposal.initialGrant.capabilities),
      permittedProjectIDs: proposal.initialGrant.projectAllowlist,
      actionProfileCeiling: .observe
    )
  }

  /// Maps the crypto-local intent vocabulary onto the authoritative one.
  ///
  /// `CompanionCrypto` must not depend on `MacBridgeCore`, so pairing states
  /// its intent in its own closed enum and the translation lives here.
  static func capabilities(
    _ intents: Set<PairedDeviceCapabilityIntent>
  ) -> Set<DeviceCapability> {
    Set(
      intents.map { intent in
        switch intent {
        case .observe: DeviceCapability.view
        }
      })
  }
}

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
    // **Ask with the session's real identity, never a reconstructed one.**
    // `validate` compares identities whole — connection ID included — so
    // passing a stand-in value made this return false for every command from
    // every device: the transport worked, the grant was valid, and the
    // gateway denied `revokedDevice` regardless. The lookup is by the pair the
    // gateway actually knows, and the session ID is still checked, so a stale
    // session is refused exactly as before.
    guard let identity = await coordinator.currentIdentity(deviceID: deviceID),
      identity.sessionID == sessionID,
      let record = try? await coordinator.validate(identity)
    else {
      return false
    }
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
    // The Mac's own verdict, on the Mac's own output. A device that reports a
    // command as "unknown" cannot say whether the Mac ran it, refused it, or
    // never saw it — three states with three different fixes. The kind and the
    // outcome are a closed vocabulary; no thread, path, or prompt is named.
    FileHandle.standardError.write(
      Data("codex-micro: command.\(command.body.kind.rawValue) — \(outcome)\n".utf8))
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
