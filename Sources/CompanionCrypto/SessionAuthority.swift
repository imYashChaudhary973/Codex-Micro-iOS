import CompanionProtocol
import CryptoKit
import Foundation

/// Closed authenticated-session failure vocabulary.
///
/// Every case is a compile-time constant: no case carries wire content, key
/// material, secret-derived data, counter values, or a free-form string.
///
/// The vocabulary is split by trust state, and **``authenticationFailed`` is
/// the only reason the host handshake ever produces**. Until the device has
/// signed the session transcript nothing about it may be distinguishable, so
/// an unknown device, a revoked grant, an expired grant, a rejected
/// selection, a bad signature, an unavailable authority, and a host-side
/// fault are one indistinguishable outcome (threat model §8). The specific
/// reasons exist only for sessions that already authenticated — where the
/// peer has proven it is the device the reason is about — and for the
/// device's own local failures, which never travel to a peer.
public enum SessionClosedReason: String, Error, Equatable, CaseIterable, Sendable {
  // MARK: Handshake (pre-authentication) — exactly one, collapsed

  /// The only outcome any host handshake rejection produces.
  case authenticationFailed

  // MARK: Established sessions (post-authentication)

  /// No session is registered for the device.
  case sessionUnknown
  /// A newer authenticated session replaced this one (plan §2 invariant 18).
  case sessionSuperseded
  /// The session passed its monotonic expiry deadline.
  case sessionExpired
  /// The Mac-stored grant carries a revocation tombstone.
  case deviceRevoked
  /// The Mac-stored grant is expired.
  case grantExpired
  /// The Mac-stored grant record is gone.
  case deviceUnknown
  /// The device's current authority counters differ from the ones this
  /// session was established under.
  case authorizationChanged
  /// The session was established under a superseded authentication
  /// generation and must reauthenticate.
  case generationStale
  /// The authentication generation reached its fixed width; the registry is
  /// latched closed rather than wrapping (plan §9 counter widths).
  case generationExhausted
  /// The grant authority is unavailable, so no authorization can be
  /// confirmed (plan §2 invariant 15).
  case authorityUnavailable

  // MARK: Device-side local failures (never sent to a peer)

  /// The proposed or echoed selection is not exactly the supported tuple.
  case selectionRejected
  /// A presented long-term or ephemeral public key is not a valid X9.63
  /// P-256 point.
  case deviceKeyInvalid
  /// The injected device signer produced no usable 64-byte signature.
  case deviceSignatureUnavailable
  /// The host transcript signature does not verify against the pinned host
  /// identity over the independently reconstructed transcript.
  case hostSignatureInvalid
  /// The host reply does not correspond to the in-flight attempt.
  case malformedResponse
  /// Ephemeral ECDH or the directional key schedule failed.
  case keyAgreementFailed
  /// The injected randomness source did not deliver the requested bytes.
  case entropyUnavailable
}

/// Where a closed reason is being turned into a wire close code.
///
/// The mapping is a function of the **call site**, not of the reason alone,
/// so a listener holding a specific reason cannot accidentally re-leak it on
/// a connection that never authenticated.
public enum SessionCloseContext: Sendable {
  /// Anything that failed during the three-message handshake.
  case handshake
  /// A session that authenticated and is now being closed.
  case authenticatedSession
}

extension SessionClosedReason {
  /// The closed wire close code for this reason at one call site.
  ///
  /// Every handshake close is ``SecureCloseReason/authenticationFailed``,
  /// whatever the internal reason was.
  public func closeReason(in context: SessionCloseContext) -> SecureCloseReason {
    switch context {
    case .handshake:
      return .authenticationFailed
    case .authenticatedSession:
      switch self {
      case .deviceRevoked: return .deviceRevoked
      case .grantExpired, .sessionExpired: return .grantExpired
      case .authorizationChanged, .generationStale, .generationExhausted:
        return .authorizationChanged
      case .sessionSuperseded: return .sessionReplaced
      case .authenticationFailed, .sessionUnknown, .deviceUnknown, .authorityUnavailable,
        .selectionRejected, .deviceKeyInvalid, .deviceSignatureUnavailable, .hostSignatureInvalid,
        .malformedResponse, .keyAgreementFailed, .entropyUnavailable:
        return .authenticationFailed
      }
    }
  }
}

/// Fixed authenticated-session policy values (plan §9, ADR §9).
public enum SessionPolicy {
  /// Exact session-nonce size in bytes (256 random bits each side).
  public static let nonceByteCount = SecureTransportLimits.nonceByteCount
  /// Exact CSPRNG draw backing one fresh session identifier (128 bits).
  public static let sessionIDByteCount = 16
  /// Exact CSPRNG draw backing one fresh ephemeral P-256 scalar.
  public static let ephemeralScalarByteCount = 32
  /// The generation every fresh registry starts at.
  public static let firstGenerationValue: UInt64 = 1
  /// How long an offered handshake may wait for its confirmation, on the
  /// monotonic clock. It matches the ADR §9 authentication deadline the
  /// listener enforces separately, so an abandoned handshake cannot hold
  /// state — or an ephemeral private key — indefinitely.
  public static let handshakeCompletionSeconds = UInt64(
    SecureTransportLimits.authenticationDeadlineSeconds)

  /// The one selection this build authenticates: the exact supported major,
  /// the exact supported minor, and the complete supported feature set.
  ///
  /// Session authentication accepts nothing else — an unknown feature, an
  /// absent feature, a future minor, and a foreign major are each rejected,
  /// and Phase 2 defines no approval feature to negotiate (plan §1).
  ///
  /// Phase 2 supports exactly one minor, so taking the highest supported one
  /// is that minor. A future step that supports several must replace this
  /// single required tuple with an explicit per-session choice rather than
  /// silently authenticating the highest.
  public static func requiredSelection() throws -> SecureProtocolSelection {
    guard let minor = SecureProtocolNegotiation.supportedMinors.max() else {
      throw SessionClosedReason.selectionRejected
    }
    guard
      let selection = try? SecureProtocolSelection(
        major: SecureProtocolNegotiation.supportedMajor,
        minor: minor,
        features: SecureProtocolNegotiation.supportedFeatures
      )
    else {
      throw SessionClosedReason.selectionRejected
    }
    return selection
  }
}

// MARK: - Signing seam

/// Long-term identity signing seam over canonical session-domain statement
/// bytes: the device signs its ``SessionAuthenticationStatement`` and then the
/// full ``SessionTranscript``; the host signs the same transcript.
///
/// The Mac's real signer is the Secure Enclave-backed identity in
/// `MacBridgeServer` and the device's is its own Secure Enclave key; neither
/// is imported here, so this module never holds private key material. The
/// canonical domain separator inside the signed bytes keeps a signature made
/// for one statement type from ever verifying as another (ADR §11).
public protocol SessionStatementSigner: Sendable {
  /// Signs canonical statement bytes, returning exactly 64 raw `r||s` bytes.
  func signSessionStatement(_ canonicalBytes: Data) throws -> Data
}

// MARK: - Authority seam

/// Closed liveness vocabulary of one Mac-stored device grant.
public enum SessionAuthorityLiveness: String, Equatable, CaseIterable, Sendable {
  /// The grant is current: no tombstone and no passed expiry instant.
  case live
  /// The grant carries a revocation tombstone.
  case revoked
  /// The grant is expired, by tombstone or by a passed expiry instant.
  case expired
}

/// One read of the Mac's authoritative state for a single device.
///
/// This value is the **only** source of the authority counters a session is
/// admitted under (plan §2 invariant 1). Nothing a phone presents may
/// contribute to it: no authentication message carries a grant revision,
/// authorized-view epoch, or host generation in either direction, so there is
/// no phone-presented value that could override it.
public struct SessionAuthoritySnapshot: Equatable, Sendable {
  public let deviceID: UUID
  /// The device's long-term X9.63 public key as stored by the Mac.
  public let devicePublicKeyX963: Data
  public let grantRevision: UInt64
  public let authorizedViewEpoch: UInt64
  public let hostGeneration: UInt64
  /// The authority's monotonic commit sequence at the instant of this read.
  ///
  /// It linearizes authentication against authorization changes: the session
  /// registry keeps the highest sequence any committed change published, and
  /// a handshake holding an older sequence is refused at commit even if its
  /// snapshot was read before the change (plan §2 invariant 11).
  public let authorityCommitSequence: UInt64
  public let liveness: SessionAuthorityLiveness
  /// Seconds of grant lifetime remaining at the instant of this read, or
  /// `nil` when the grant carries no expiry.
  ///
  /// This is the value expiry is **enforced** on: it is a duration, never a
  /// wall-clock instant, and the coordinator converts it once, at
  /// authentication, into a deadline on its monotonic seam, so a later
  /// backwards wall-clock step cannot extend an active session.
  public let remainingLifetimeSeconds: UInt64?
  /// The grant's wall-clock expiry instant, recorded on the session for the
  /// Mac's own expiry scheduling. It never decides whether a session is live.
  public let grantExpiresAtEpochSeconds: UInt64?

  public init(
    deviceID: UUID,
    devicePublicKeyX963: Data,
    grantRevision: UInt64,
    authorizedViewEpoch: UInt64,
    hostGeneration: UInt64,
    authorityCommitSequence: UInt64,
    liveness: SessionAuthorityLiveness,
    remainingLifetimeSeconds: UInt64?,
    grantExpiresAtEpochSeconds: UInt64? = nil
  ) throws {
    guard (try? SecureP256KeyEncoding.signingPublicKey(fromX963: devicePublicKeyX963)) != nil else {
      throw SessionClosedReason.deviceKeyInvalid
    }
    self.deviceID = deviceID
    self.devicePublicKeyX963 = devicePublicKeyX963
    self.grantRevision = grantRevision
    self.authorizedViewEpoch = authorizedViewEpoch
    self.hostGeneration = hostGeneration
    self.authorityCommitSequence = authorityCommitSequence
    self.liveness = liveness
    self.remainingLifetimeSeconds = remainingLifetimeSeconds
    self.grantExpiresAtEpochSeconds = grantExpiresAtEpochSeconds
  }

  /// The device's validated long-term signing key.
  func signingPublicKey() throws -> P256.Signing.PublicKey {
    guard let key = try? SecureP256KeyEncoding.signingPublicKey(fromX963: devicePublicKeyX963)
    else {
      throw SessionClosedReason.deviceKeyInvalid
    }
    return key
  }
}

/// The Mac-authority seam the session coordinator queries.
///
/// The production implementation is the `MacBridgeCore` device-grant
/// authority, wired by the Mac assembly; `CompanionCrypto` must not depend on
/// it, so authentication reads through this protocol instead. Returning `nil`
/// means no grant record exists for the device; throwing means the authority
/// itself is unavailable, which denies authentication outright rather than
/// falling back to any cached or presented value.
///
/// **Cross-module obligation.** The wall-clock expiry instant belongs to the
/// Mac authority: it must report `expired` liveness once that instant passes,
/// persist the expiry tombstone, publish the resulting commit sequence, and
/// invalidate that device's session. The duration this seam returns only
/// fixes the session's own monotonic deadline; it cannot detect an expiry the
/// authority has not published.
public protocol SessionAuthorityProviding: Sendable {
  func authoritySnapshot(deviceID: UUID) async throws -> SessionAuthoritySnapshot?
}

/// Deterministic in-memory authority for tests, the deterministic reference
/// flow, and the Step 2.14 acceptance host.
///
/// It stores a host-wide generation, a monotonic commit sequence, and one
/// record per device, and exposes explicit mutators for every authorization
/// change Phase 2 recognizes, so a test can advance counters, revoke, expire,
/// shorten a grant's remaining lifetime, or take the whole authority offline
/// between two coordinator calls. Every mutation advances the commit
/// sequence, exactly as the real persist-before-visible authority does.
/// Counter mutators fail the authority closed at `UInt64.max` instead of
/// wrapping (plan §9). The Mac's persistent authority is the real source of
/// truth; nothing here is authoritative or persisted.
public final class InMemorySessionAuthority: SessionAuthorityProviding, @unchecked Sendable {
  private struct Record {
    var devicePublicKeyX963: Data
    var grantRevision: UInt64
    var authorizedViewEpoch: UInt64
    var liveness: SessionAuthorityLiveness
    var remainingLifetimeSeconds: UInt64?
    var grantExpiresAtEpochSeconds: UInt64?
  }

  private let lock = NSLock()
  private var records: [UUID: Record] = [:]
  private var hostGeneration: UInt64
  private var commitSequence: UInt64
  private var isUnavailable = false

  public init(hostGeneration: UInt64 = 1, commitSequence: UInt64 = 1) {
    self.hostGeneration = hostGeneration
    self.commitSequence = commitSequence
  }

  /// The authority's current monotonic commit sequence, which an
  /// authorization-change flow publishes to the session registry.
  public var currentCommitSequence: UInt64 {
    lock.lock()
    defer { lock.unlock() }
    return commitSequence
  }

  /// Adds or replaces one device's authoritative record.
  public func setDevice(
    deviceID: UUID,
    devicePublicKeyX963: Data,
    grantRevision: UInt64 = 1,
    authorizedViewEpoch: UInt64 = 1,
    liveness: SessionAuthorityLiveness = .live,
    remainingLifetimeSeconds: UInt64? = nil,
    grantExpiresAtEpochSeconds: UInt64? = nil
  ) throws {
    guard (try? SecureP256KeyEncoding.signingPublicKey(fromX963: devicePublicKeyX963)) != nil else {
      throw SessionClosedReason.deviceKeyInvalid
    }
    lock.lock()
    defer { lock.unlock() }
    records[deviceID] = Record(
      devicePublicKeyX963: devicePublicKeyX963,
      grantRevision: grantRevision,
      authorizedViewEpoch: authorizedViewEpoch,
      liveness: liveness,
      remainingLifetimeSeconds: remainingLifetimeSeconds,
      grantExpiresAtEpochSeconds: grantExpiresAtEpochSeconds
    )
    advanceCommitSequenceLocked()
  }

  /// Removes a device's record, modelling an unknown device.
  @discardableResult
  public func removeDevice(_ deviceID: UUID) -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    records.removeValue(forKey: deviceID)
    advanceCommitSequenceLocked()
    return commitSequence
  }

  /// Sets one device's liveness, modelling revocation or expiry.
  @discardableResult
  public func setLiveness(
    _ liveness: SessionAuthorityLiveness,
    forDevice deviceID: UUID
  ) -> UInt64 {
    mutate(deviceID) { $0.liveness = liveness }
  }

  /// Sets one device's remaining grant lifetime.
  @discardableResult
  public func setRemainingLifetimeSeconds(
    _ seconds: UInt64?,
    forDevice deviceID: UUID
  ) -> UInt64 {
    mutate(deviceID) { $0.remainingLifetimeSeconds = seconds }
  }

  /// Advances one device's grant revision, modelling a grant reduction.
  @discardableResult
  public func advanceGrantRevision(forDevice deviceID: UUID) -> UInt64 {
    mutate(deviceID) { record in
      guard let next = Self.bumped(record.grantRevision) else {
        isUnavailable = true
        return
      }
      record.grantRevision = next
    }
  }

  /// Advances one device's authorized-view epoch, modelling a scope change.
  @discardableResult
  public func advanceAuthorizedViewEpoch(forDevice deviceID: UUID) -> UInt64 {
    mutate(deviceID) { record in
      guard let next = Self.bumped(record.authorizedViewEpoch) else {
        isUnavailable = true
        return
      }
      record.authorizedViewEpoch = next
    }
  }

  /// Advances the host-wide generation, modelling global invalidation.
  @discardableResult
  public func advanceHostGeneration() -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    guard let next = Self.bumped(hostGeneration) else {
      isUnavailable = true
      return commitSequence
    }
    hostGeneration = next
    advanceCommitSequenceLocked()
    return commitSequence
  }

  /// Takes the whole authority offline, or brings it back.
  public func setUnavailable(_ unavailable: Bool) {
    lock.lock()
    defer { lock.unlock() }
    isUnavailable = unavailable
  }

  public func authoritySnapshot(deviceID: UUID) async throws -> SessionAuthoritySnapshot? {
    try currentSnapshot(deviceID: deviceID)
  }

  /// Synchronous body of ``authoritySnapshot(deviceID:)``; the lock is taken
  /// outside any asynchronous context.
  public func currentSnapshot(deviceID: UUID) throws -> SessionAuthoritySnapshot? {
    lock.lock()
    defer { lock.unlock() }
    guard !isUnavailable else {
      throw SessionClosedReason.authorityUnavailable
    }
    guard let record = records[deviceID] else { return nil }
    return try SessionAuthoritySnapshot(
      deviceID: deviceID,
      devicePublicKeyX963: record.devicePublicKeyX963,
      grantRevision: record.grantRevision,
      authorizedViewEpoch: record.authorizedViewEpoch,
      hostGeneration: hostGeneration,
      authorityCommitSequence: commitSequence,
      liveness: record.liveness,
      remainingLifetimeSeconds: record.remainingLifetimeSeconds,
      grantExpiresAtEpochSeconds: record.grantExpiresAtEpochSeconds
    )
  }

  @discardableResult
  private func mutate(_ deviceID: UUID, _ body: (inout Record) -> Void) -> UInt64 {
    lock.lock()
    defer { lock.unlock() }
    guard var record = records[deviceID] else { return commitSequence }
    body(&record)
    records[deviceID] = record
    advanceCommitSequenceLocked()
    return commitSequence
  }

  private func advanceCommitSequenceLocked() {
    guard let next = Self.bumped(commitSequence) else {
      isUnavailable = true
      return
    }
    commitSequence = next
  }

  private static func bumped(_ counter: UInt64) -> UInt64? {
    counter < UInt64.max ? counter + 1 : nil
  }
}
