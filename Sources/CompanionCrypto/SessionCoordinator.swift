import CompanionProtocol
import CryptoKit
import Foundation

/// The host's reply to a session authentication request: message 2 of 3.
///
/// Producing it commits **nothing**. No session exists, no session is
/// displaced, no key is usable, and no authority state is disclosed until the
/// device returns a valid ``SecureSessionAuthConfirmation`` over the exact
/// transcript this offer's contributions define.
public struct HostSessionOffer: Sendable {
  /// The reply to send to the device.
  public let response: SecureSessionAuthResponse
  /// The session ID this handshake would establish.
  public var sessionID: UUID { response.sessionID }
}

/// One established host-side session: its registry record, the transcript
/// both endpoints signed, and the two directional frame endpoints.
///
/// Counters start at 0 in each direction and the frame header binds this
/// session's fresh session ID, so no frame from any previous session or
/// connection can open here.
public struct EstablishedHostSession: Sendable {
  public let record: AuthenticatedSessionRecord
  public let transcript: SessionTranscript
  /// Opens client-to-server frames.
  public var inbound: SecureFrameOpener
  /// Seals server-to-client frames.
  public var outbound: SecureFrameSealer

  public var identity: AuthenticatedSessionIdentity { record.identity }
  /// The Mac authority counters this session is authorized under. They are
  /// host-side state: Step 2.8 delivers them to the device only inside
  /// sealed post-authentication traffic.
  public var grantRevision: UInt64 { record.grantRevision }
  public var authorizedViewEpoch: UInt64 { record.authorizedViewEpoch }
  public var hostGeneration: UInt64 { record.hostGeneration }
}

extension EstablishedHostSession: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the session holds both directional frame keys.
  public var description: String { "EstablishedHostSession(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// Everything one completed authentication produces.
public struct HostSessionAuthentication: Sendable {
  /// The newly registered session.
  public let session: EstablishedHostSession
  /// The device's previous session, atomically replaced by this one. The
  /// caller must close that connection (plan §2 invariant 18).
  public let supersededSession: AuthenticatedSessionIdentity?
}

extension HostSessionAuthentication: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: it carries the established session's directional keys.
  public var description: String { "HostSessionAuthentication(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// Host-side, transport-independent authenticated-session state machine
/// (plan Step 2.6).
///
/// The coordinator owns session choreography and nothing else: it holds no
/// socket, no Keychain, no grant store, and no Codex access. Its seams — Mac
/// authority, long-term host signer, session registry, CSPRNG, and monotonic
/// clock — are injected, so the Secure Enclave identity in `MacBridgeServer`
/// and the device-grant authority in `MacBridgeCore` are never imported here.
///
/// **Three messages, one commit point.** Like Step 2.5's pairing, the
/// handshake is mutual and only completes when both endpoints have signed the
/// same transcript:
///
/// 1. `SecureSessionAuthRequest` — the device's ephemeral key, nonce, and a
///    signature over the ``SessionAuthenticationStatement``. This is a
///    first-order binding to the device's long-term key; it contains no host
///    contribution and is therefore **never treated as proof of freshness**.
/// 2. `SecureSessionAuthResponse` — the host's fresh session ID, ephemeral
///    key, and nonce, signed into the full ``SessionTranscript``. It carries
///    no authority metadata, so nothing is disclosed to a peer that has not
///    proven freshness.
/// 3. `SecureSessionAuthConfirmation` — the device's signature over that same
///    transcript. Only this proves the peer holds the long-term key **now**,
///    for **these** host contributions.
///
/// Security-relevant ordering, fixed by plan §2:
///
/// - **Nothing commits before message 3 verifies.** No registration, no
///   supersession, no superseded identity, and no frame key escapes until
///   then, so a replayed message 1 cannot register a session, cannot evict a
///   live session, and learns nothing.
/// - **Mac authority is the only source of truth** (invariant 1). The
///   authority is read at message 1 and again at commit; the counters the
///   session is admitted under come from the commit-time read alone. No
///   authentication message carries a counter in either direction.
/// - **Linearizable against authorization changes** (invariant 11). Every
///   snapshot carries the authority's monotonic commit sequence, and the
///   registry refuses any commit whose snapshot predates the published
///   watermark, so a handshake that was in flight across a revocation cannot
///   land after it.
/// - **Exact negotiation** (invariant 6). The request's selection must equal
///   the one supported tuple; an unknown feature, an absent feature, a future
///   minor, and a foreign major are each rejected. Phase 2 defines no
///   approval feature.
/// - **Fresh material every time.** A fresh session ID, ephemeral key, and
///   256-bit nonce per attempt, with directional keys derived from the
///   resulting transcript hash, so reconnects share no key or counter space.
/// - **One indistinguishable rejection.** Every handshake failure throws
///   ``SessionClosedReason/authenticationFailed``, so an unauthenticated peer
///   cannot probe whether a device, grant, or session exists.
public actor SessionCoordinator {
  private struct PendingHandshake {
    let sessionID: UUID
    let deviceID: UUID
    let transcript: SessionTranscript
    let ephemeral: P256.KeyAgreement.PrivateKey
    let requestBinding: Data
    let deadlineMonotonicSeconds: UInt64
  }

  private struct Registration {
    let record: AuthenticatedSessionRecord
    let superseded: AuthenticatedSessionIdentity?
  }

  private let hostID: UUID
  private let hostTLSSPKIFingerprint: Data
  private let authority: any SessionAuthorityProviding
  private let signer: any SessionStatementSigner
  private let store: any AuthenticatedSessionStore
  private let random: any PairingRandomSource
  private let monotonicClock: @Sendable () -> UInt64
  private let requiredSelection: SecureProtocolSelection
  /// At most one in-flight handshake per transport connection; a new message
  /// 1 on the same connection replaces the previous offer, so pending state
  /// is bounded by the listener's connection cap.
  private var pending: [UUID: PendingHandshake] = [:]

  /// - Parameters:
  ///   - hostID: Opaque, non-secret host identifier, bound into the
  ///     statement the device signs so one host's request cannot be
  ///     presented to another.
  ///   - hostTLSSPKIFingerprint: The current TLS SPKI fingerprint, bound into
  ///     the session transcript so a session is tied to the same pinned
  ///     channel identity pairing bound.
  ///   - authority: The Mac-authority seam; the only source of the grant
  ///     revision, authorized-view epoch, and host generation.
  ///   - signer: Seam producing host signatures over transcript bytes.
  ///   - store: Session registry. Several coordinators may share one.
  ///   - random: CSPRNG seam.
  ///   - monotonicClock: Monotonic-seconds seam that enforces handshake
  ///     deadlines and active-session expiry; no wall clock participates, so
  ///     a backwards wall-clock step can never extend a session.
  public init(
    hostID: UUID,
    hostTLSSPKIFingerprint: Data,
    authority: any SessionAuthorityProviding,
    signer: any SessionStatementSigner,
    store: any AuthenticatedSessionStore = InMemoryAuthenticatedSessionStore(),
    random: any PairingRandomSource = SystemPairingRandomSource(),
    monotonicClock: @escaping @Sendable () -> UInt64 = PairingMonotonicClock.system
  ) throws {
    try requireExactCryptoByteCount(
      hostTLSSPKIFingerprint, SPKIFingerprint.byteCount, field: "hostTLSSPKIFingerprint")
    self.hostID = hostID
    self.hostTLSSPKIFingerprint = hostTLSSPKIFingerprint
    self.authority = authority
    self.signer = signer
    self.store = store
    self.random = random
    self.monotonicClock = monotonicClock
    self.requiredSelection = try SessionPolicy.requiredSelection()
  }

  // MARK: - Handshake

  /// Answers message 1 with message 2, committing nothing.
  ///
  /// The device's statement signature is verified against the key the Mac
  /// authority stores for that device, never against a key the request
  /// presents. Every rejection is the single collapsed handshake reason.
  public func beginAuthentication(
    request: SecureSessionAuthRequest,
    connectionID: UUID
  ) async throws -> HostSessionOffer {
    do {
      return try await offer(request: request, connectionID: connectionID)
    } catch {
      throw SessionClosedReason.authenticationFailed
    }
  }

  /// Completes the handshake with message 3 and registers the session.
  ///
  /// This is the only commit point: the device's signature over the full
  /// transcript proves it holds the long-term key for **these** host
  /// contributions, and only then does the coordinator re-read the authority,
  /// derive frame keys, and atomically replace the device's previous session.
  public func completeAuthentication(
    confirmation: SecureSessionAuthConfirmation,
    connectionID: UUID
  ) async throws -> HostSessionAuthentication {
    do {
      return try await commit(confirmation: confirmation, connectionID: connectionID)
    } catch {
      throw SessionClosedReason.authenticationFailed
    }
  }

  /// Drops any in-flight handshake for a connection the transport closed.
  public func abandonHandshake(connectionID: UUID) {
    pending.removeValue(forKey: connectionID)
    expirePendingHandshakes()
  }

  /// The number of in-flight handshakes, after expiring stale ones.
  public func pendingHandshakeCount() -> Int {
    expirePendingHandshakes()
    return pending.count
  }

  // MARK: - Continued use

  /// The registry state of one session, if it is still usable.
  ///
  /// The session must be the device's current session, must belong to the
  /// current authentication generation, must not have passed its monotonic
  /// expiry deadline, and must still match the device's current Mac
  /// authority. Every other outcome is a distinct closed reason — the peer
  /// has authenticated, so specificity leaks nothing — and the caller closes
  /// the connection with it.
  public func validate(
    _ identity: AuthenticatedSessionIdentity
  ) async throws -> AuthenticatedSessionRecord {
    let state = store.state()
    try Self.requireOperable(state)
    let record = try Self.requireCurrent(identity, in: state)
    guard !record.isExpired(atMonotonicSeconds: monotonicClock()) else {
      throw SessionClosedReason.sessionExpired
    }
    let snapshot = try await liveAuthority(deviceID: identity.deviceID)
    guard record.matches(snapshot) else {
      throw SessionClosedReason.authorizationChanged
    }
    // Re-check after the authority read: a concurrent reauthentication or
    // generation advance may have landed while the authority call was in
    // flight, and a validation must never outlive the session it validated.
    let committed = store.state()
    try Self.requireOperable(committed)
    _ = try Self.requireCurrent(identity, in: committed)
    return record
  }

  /// The device's current session, if it is still locally usable.
  ///
  /// The free local checks — generation and monotonic expiry — are applied,
  /// so a stale or expired record is never handed back as active. Authority
  /// freshness needs ``validate(_:)``.
  public func activeSession(forDevice deviceID: UUID) -> AuthenticatedSessionRecord? {
    let state = store.state()
    guard !state.isGenerationExhausted, let record = state.sessions[deviceID] else { return nil }
    return isLocallyUsable(record, in: state) ? record : nil
  }

  /// Every locally usable session, ordered by device ID.
  public func activeSessions() -> [AuthenticatedSessionRecord] {
    let state = store.state()
    guard !state.isGenerationExhausted else { return [] }
    return state.sessions.values
      .filter { isLocallyUsable($0, in: state) }
      .sorted { $0.identity.deviceID.uuidString < $1.identity.deviceID.uuidString }
  }

  /// The registry's current authentication generation.
  public func authenticationGeneration() -> AuthenticationGeneration {
    store.state().generation
  }

  /// The highest authority commit sequence published to this registry.
  public func publishedAuthorityCommit() -> UInt64 {
    store.state().authorityWatermark
  }

  // MARK: - Authorization change and expiry

  /// Publishes a committed authorization change to the registry.
  ///
  /// The Mac's authorization-change flow calls this **after** the authority
  /// commit is durable and **before** it closes the affected connections. Any
  /// handshake still holding an older snapshot is then refused at its commit
  /// point, so a session can never be registered under authorization that has
  /// already been superseded (plan §2 invariant 11). The watermark is
  /// monotonic; a lower sequence is ignored.
  @discardableResult
  public func publishAuthorityCommit(sequence: UInt64) -> UInt64 {
    store.mutate { state in
      state.authorityWatermark = max(state.authorityWatermark, sequence)
      return state.authorityWatermark
    }
  }

  /// Invalidates the session of one device after a revocation, grant
  /// reduction, scope reduction, or expiry, returning the identity the
  /// transport must close.
  @discardableResult
  public func invalidateSessions(forDevice deviceID: UUID) -> AuthenticatedSessionIdentity? {
    store.mutate { state in
      state.sessions.removeValue(forKey: deviceID)?.identity
    }
  }

  /// Removes one exact session, if it is still the device's current one.
  @discardableResult
  public func close(_ identity: AuthenticatedSessionIdentity) -> AuthenticatedSessionIdentity? {
    store.mutate { state in
      guard state.sessions[identity.deviceID]?.identity == identity else { return nil }
      return state.sessions.removeValue(forKey: identity.deviceID)?.identity
    }
  }

  /// Advances the authentication generation, invalidating **every** session.
  ///
  /// This is the runtime boundary the spike's lifecycle model lacked: a
  /// listener restart, a global invalidation, or a host-generation change
  /// calls it, and every returned identity must be closed and reauthenticated.
  /// At the fixed-width ceiling it fails closed instead of wrapping — the
  /// generation stays put, the registry is emptied, the registry latches so
  /// no coordinator over it may authenticate again — and the invalidated
  /// identities are still returned so the caller can close those connections.
  @discardableResult
  public func advanceAuthenticationGeneration() -> GenerationAdvance {
    pending.removeAll()
    return store.mutate { state in
      let invalidated = Self.identities(of: state.sessions)
      state.sessions = [:]
      guard let next = try? state.generation.advanced() else {
        state.isGenerationExhausted = true
        return GenerationAdvance(
          invalidated: invalidated, generation: state.generation, isExhausted: true)
      }
      state.generation = next
      return GenerationAdvance(invalidated: invalidated, generation: next, isExhausted: false)
    }
  }

  /// Removes every session whose authority is no longer live, whose
  /// authority counters advanced, whose generation is stale, or which passed
  /// its monotonic expiry deadline, returning each identity with the closed
  /// reason the transport must close it with.
  public func sweepInvalidSessions() async -> [SessionInvalidation] {
    let state = store.state()
    let now = monotonicClock()
    var invalidations: [SessionInvalidation] = []
    for record in state.sessions.values.sorted(by: {
      $0.identity.deviceID.uuidString < $1.identity.deviceID.uuidString
    }) {
      if let reason = await invalidationReason(
        for: record, generation: state.generation, monotonicNow: now)
      {
        invalidations.append(SessionInvalidation(identity: record.identity, reason: reason))
      }
    }
    guard !invalidations.isEmpty else { return [] }
    return store.mutate { state in
      invalidations.compactMap { invalidation in
        guard let stored = state.sessions[invalidation.identity.deviceID],
          stored.identity == invalidation.identity
        else {
          return nil
        }
        // Re-read the generation at commit: an advance during the sweep has
        // already emptied the registry, and anything registered afterwards
        // belongs to a newer generation than the one evaluated above.
        guard stored.generation == state.generation || invalidation.reason == .generationStale
        else {
          return nil
        }
        state.sessions.removeValue(forKey: invalidation.identity.deviceID)
        return invalidation
      }
    }
  }

  // MARK: - Handshake internals

  private func offer(
    request: SecureSessionAuthRequest,
    connectionID: UUID
  ) async throws -> HostSessionOffer {
    try Self.requireOperable(store.state())
    expirePendingHandshakes()
    let snapshot = try await liveAuthority(deviceID: request.deviceID)
    guard request.selection == requiredSelection,
      (try? SecureProtocolNegotiation.accept(request.selection)) != nil
    else {
      throw SessionClosedReason.selectionRejected
    }
    let statement = try SessionAuthenticationStatement(hostID: hostID, request: request)
    guard
      (try? SecureP256KeyEncoding.keyAgreementPublicKey(
        fromX963: request.deviceEphemeralPublicKey)) != nil
    else {
      throw SessionClosedReason.deviceKeyInvalid
    }
    guard
      SecureTranscriptSignature.isValid(
        request.transcriptSignature,
        for: statement.canonicalEncoding(),
        publicKey: try snapshot.signingPublicKey()
      )
    else {
      throw SessionClosedReason.authenticationFailed
    }

    let sessionID = UUID(canonicalBytes: try entropy(SessionPolicy.sessionIDByteCount))
    let hostNonce = try entropy(SessionPolicy.nonceByteCount)
    let hostEphemeral = try ephemeralPrivateKey()
    let transcript = try SessionTranscript(
      sessionID: sessionID,
      deviceID: snapshot.deviceID,
      selection: request.selection,
      deviceEphemeralPublicKey: request.deviceEphemeralPublicKey,
      deviceNonce: request.deviceNonce,
      hostEphemeralPublicKey: hostEphemeral.publicKey.x963Representation,
      hostNonce: hostNonce,
      hostTLSSPKIFingerprint: hostTLSSPKIFingerprint
    )
    let signature = try hostSignature(over: transcript)
    let response = try SecureSessionAuthResponse(
      sessionID: sessionID,
      selection: transcript.selection,
      hostEphemeralPublicKey: transcript.hostEphemeralPublicKey,
      hostNonce: hostNonce,
      transcriptSignature: signature
    )
    // Purely local state: nothing here is registered, nothing is displaced,
    // and the ephemeral private key never leaves this actor.
    pending[connectionID] = PendingHandshake(
      sessionID: sessionID,
      deviceID: snapshot.deviceID,
      transcript: transcript,
      ephemeral: hostEphemeral,
      requestBinding: statement.canonicalHash(),
      deadlineMonotonicSeconds: try Self.handshakeDeadline(monotonicNow: monotonicClock())
    )
    return HostSessionOffer(response: response)
  }

  private func commit(
    confirmation: SecureSessionAuthConfirmation,
    connectionID: UUID
  ) async throws -> HostSessionAuthentication {
    try Self.requireOperable(store.state())
    expirePendingHandshakes()
    guard let handshake = pending.removeValue(forKey: connectionID) else {
      throw SessionClosedReason.authenticationFailed
    }
    guard confirmation.sessionID == handshake.sessionID,
      confirmation.deviceID == handshake.deviceID
    else {
      throw SessionClosedReason.authenticationFailed
    }

    // The authority is re-read at the commit point, so the session is
    // admitted under the authorization current *now*, not the one that was
    // current when the offer was made.
    let snapshot = try await liveAuthority(deviceID: handshake.deviceID)
    guard
      SecureTranscriptSignature.isValid(
        confirmation.transcriptSignature,
        for: handshake.transcript.canonicalEncoding(),
        publicKey: try snapshot.signingPublicKey()
      )
    else {
      throw SessionClosedReason.authenticationFailed
    }

    let keys = try Self.frameKeys(
      hostEphemeral: handshake.ephemeral,
      deviceEphemeralPublicKey: handshake.transcript.deviceEphemeralPublicKey,
      transcript: handshake.transcript
    )
    let registration = try register(
      identity: AuthenticatedSessionIdentity(
        sessionID: handshake.sessionID,
        connectionID: connectionID,
        deviceID: snapshot.deviceID
      ),
      snapshot: snapshot,
      requestBinding: handshake.requestBinding
    )
    return HostSessionAuthentication(
      session: EstablishedHostSession(
        record: registration.record,
        transcript: handshake.transcript,
        inbound: try SecureFrameOpener(
          key: keys.clientToServer,
          connectionID: handshake.sessionID,
          direction: .clientToServer
        ),
        outbound: try SecureFrameSealer(
          key: keys.serverToClient,
          connectionID: handshake.sessionID,
          direction: .serverToClient
        )
      ),
      supersededSession: registration.superseded
    )
  }

  /// Commits the one-active-session replacement and the authority-watermark
  /// check inside the store's own critical section, so two coordinators
  /// sharing one store still leave exactly one surviving session per device
  /// and neither can land under superseded authorization.
  private func register(
    identity: AuthenticatedSessionIdentity,
    snapshot: SessionAuthoritySnapshot,
    requestBinding: Data
  ) throws -> Registration {
    let now = monotonicClock()
    let expiresAt = try Self.expiryDeadline(snapshot: snapshot, monotonicNow: now)
    let outcome = store.mutate { state -> Result<Registration, SessionClosedReason> in
      guard !state.isGenerationExhausted else {
        return .failure(.generationExhausted)
      }
      guard snapshot.authorityCommitSequence >= state.authorityWatermark else {
        return .failure(.authorizationChanged)
      }
      if let existing = state.sessions[identity.deviceID],
        existing.requestBinding == requestBinding
      {
        return .failure(.authenticationFailed)
      }
      state.authorityWatermark = max(state.authorityWatermark, snapshot.authorityCommitSequence)
      let record = AuthenticatedSessionRecord(
        identity: identity,
        generation: state.generation,
        grantRevision: snapshot.grantRevision,
        authorizedViewEpoch: snapshot.authorizedViewEpoch,
        hostGeneration: snapshot.hostGeneration,
        authorityCommitSequence: snapshot.authorityCommitSequence,
        establishedAtMonotonicSeconds: now,
        expiresAtMonotonicSeconds: expiresAt,
        grantExpiresAtEpochSeconds: snapshot.grantExpiresAtEpochSeconds,
        requestBinding: requestBinding
      )
      let superseded = state.sessions[identity.deviceID]?.identity
      state.sessions[identity.deviceID] = record
      return .success(Registration(record: record, superseded: superseded))
    }
    return try outcome.get()
  }

  private func expirePendingHandshakes() {
    let now = monotonicClock()
    pending = pending.filter { now < $0.value.deadlineMonotonicSeconds }
  }

  // MARK: - Shared internals

  private func invalidationReason(
    for record: AuthenticatedSessionRecord,
    generation: AuthenticationGeneration,
    monotonicNow: UInt64
  ) async -> SessionClosedReason? {
    if record.generation != generation {
      return .generationStale
    }
    if record.isExpired(atMonotonicSeconds: monotonicNow) {
      return .sessionExpired
    }
    do {
      let snapshot = try await liveAuthority(deviceID: record.identity.deviceID)
      return record.matches(snapshot) ? nil : .authorizationChanged
    } catch {
      return Self.closedReason(error)
    }
  }

  private func isLocallyUsable(
    _ record: AuthenticatedSessionRecord,
    in state: AuthenticatedSessionState
  ) -> Bool {
    record.generation == state.generation
      && !record.isExpired(atMonotonicSeconds: monotonicClock())
  }

  /// Reads the device's current authority and requires a live grant.
  private func liveAuthority(deviceID: UUID) async throws -> SessionAuthoritySnapshot {
    let snapshot: SessionAuthoritySnapshot?
    do {
      snapshot = try await authority.authoritySnapshot(deviceID: deviceID)
    } catch {
      throw SessionClosedReason.authorityUnavailable
    }
    guard let snapshot else {
      throw SessionClosedReason.deviceUnknown
    }
    guard snapshot.deviceID == deviceID else {
      throw SessionClosedReason.authorityUnavailable
    }
    switch snapshot.liveness {
    case .live: return snapshot
    case .revoked: throw SessionClosedReason.deviceRevoked
    case .expired: throw SessionClosedReason.grantExpired
    }
  }

  private func entropy(_ count: Int) throws -> Data {
    guard let bytes = try? random.randomBytes(count: count), bytes.count == count else {
      throw SessionClosedReason.entropyUnavailable
    }
    return bytes
  }

  /// Mints one fresh ephemeral ECDH key from the injected CSPRNG, so
  /// deterministic tests pin the whole handshake. A drawn scalar outside the
  /// P-256 group fails closed rather than being reduced or retried.
  private func ephemeralPrivateKey() throws -> P256.KeyAgreement.PrivateKey {
    let scalar = try entropy(SessionPolicy.ephemeralScalarByteCount)
    guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: scalar) else {
      throw SessionClosedReason.entropyUnavailable
    }
    return key
  }

  private func hostSignature(over transcript: SessionTranscript) throws -> Data {
    guard let signature = try? signer.signSessionStatement(transcript.canonicalEncoding()),
      signature.count == SecureTranscriptSignature.byteCount
    else {
      throw SessionClosedReason.authenticationFailed
    }
    return signature
  }

  private static func requireOperable(_ state: AuthenticatedSessionState) throws {
    guard !state.isGenerationExhausted else {
      throw SessionClosedReason.generationExhausted
    }
  }

  private static func requireCurrent(
    _ identity: AuthenticatedSessionIdentity,
    in state: AuthenticatedSessionState
  ) throws -> AuthenticatedSessionRecord {
    guard let record = state.sessions[identity.deviceID] else {
      throw SessionClosedReason.sessionUnknown
    }
    guard record.identity == identity else {
      throw SessionClosedReason.sessionSuperseded
    }
    guard record.generation == state.generation else {
      throw SessionClosedReason.generationStale
    }
    return record
  }

  private static func frameKeys(
    hostEphemeral: P256.KeyAgreement.PrivateKey,
    deviceEphemeralPublicKey: Data,
    transcript: SessionTranscript
  ) throws -> SecureDirectionalFrameKeys {
    guard
      let sharedSecret = try? SecureKeyAgreement.sharedSecret(
        privateKey: hostEphemeral, peerPublicKeyX963: deviceEphemeralPublicKey),
      let keys = try? SecureSessionKeySchedule.frameKeys(
        sharedSecret: sharedSecret,
        sessionTranscriptHash: transcript.canonicalHash(),
        selection: transcript.selection
      )
    else {
      throw SessionClosedReason.keyAgreementFailed
    }
    return keys
  }

  private static func handshakeDeadline(monotonicNow: UInt64) throws -> UInt64 {
    let (deadline, overflow) = monotonicNow.addingReportingOverflow(
      SessionPolicy.handshakeCompletionSeconds)
    guard !overflow else {
      throw SessionClosedReason.authenticationFailed
    }
    return deadline
  }

  /// Converts the grant's remaining lifetime into a monotonic deadline once,
  /// at the commit point. A remaining lifetime that cannot be represented on
  /// the monotonic clock is malformed authority data and fails closed.
  private static func expiryDeadline(
    snapshot: SessionAuthoritySnapshot,
    monotonicNow: UInt64
  ) throws -> UInt64? {
    guard let remaining = snapshot.remainingLifetimeSeconds else { return nil }
    let (deadline, overflow) = monotonicNow.addingReportingOverflow(remaining)
    guard !overflow else {
      throw SessionClosedReason.grantExpired
    }
    return deadline
  }

  private static func identities(
    of sessions: [UUID: AuthenticatedSessionRecord]
  ) -> [AuthenticatedSessionIdentity] {
    sessions.values.map(\.identity).sorted { $0.deviceID.uuidString < $1.deviceID.uuidString }
  }

  private static func closedReason(_ error: any Error) -> SessionClosedReason {
    (error as? SessionClosedReason) ?? .authorityUnavailable
  }
}
