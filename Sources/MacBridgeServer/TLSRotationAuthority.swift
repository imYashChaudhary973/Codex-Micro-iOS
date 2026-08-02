import CompanionCrypto
import Foundation

/// A rotation statement plus its host signature, ready for delivery over
/// an authenticated session before the new TLS key is presented (two-phase
/// rotation, ADR §7).
public struct SignedTLSRotationStatement: Equatable, Sendable {
  /// The canonical rotation statement.
  public let statement: SecureRotationStatement
  /// Exactly 64 raw `r||s` host-signature bytes over the canonical
  /// statement encoding.
  public let signature: Data
}

/// Anti-rollback TLS rotation authority (ADR §7).
///
/// Owns the persisted rotation record — current generation plus
/// current/previous SPKI fingerprints — and the only two operations on it:
/// producing a host-signed rotation statement, and verifying/applying one
/// with strict generation monotonicity. Rollback, replay, pin mismatch,
/// bad signatures, and out-of-window statements are refused; the accepted
/// generation persists **before** the new state is visible, so a replayed
/// statement stays refused across process restarts. Corrupt or truncated
/// persisted state fails closed at initialization.
public final class TLSRotationAuthority: @unchecked Sendable {
  private let storage: any TLSRotationStateStorage
  private let lock = NSLock()
  private var state: TLSRotationState?

  /// Opens the authority over `storage`, strictly decoding any persisted
  /// state. A corrupt, truncated, oversized, or undecodable blob throws
  /// ``TLSRotationStateError/corruptState`` — never a fresh start.
  public init(storage: any TLSRotationStateStorage) throws {
    self.storage = storage
    if let blob = try storage.readBlob() {
      self.state = try TLSRotationStateBlobCodec.decode(blob)
    } else {
      self.state = nil
    }
  }

  /// The current persisted rotation state, or `nil` before the baseline
  /// is recorded.
  public func currentState() -> TLSRotationState? {
    lock.lock()
    defer { lock.unlock() }
    return state
  }

  /// Records the generation-0 baseline when the first TLS identity is
  /// created. Refuses to overwrite existing state.
  @discardableResult
  public func initializeBaseline(
    currentSPKIFingerprint: Data
  ) throws -> TLSRotationState {
    lock.lock()
    defer { lock.unlock() }
    guard state == nil else {
      throw TLSRotationStateError.stateAlreadyInitialized
    }
    let baseline = try TLSRotationState(
      rotationGeneration: 0,
      currentSPKIFingerprint: currentSPKIFingerprint,
      previousSPKIFingerprint: nil
    )
    try persist(baseline)
    return baseline
  }

  /// Produces a host-signed statement rotating from the stored current
  /// SPKI to `nextSPKIFingerprint` at the next generation.
  ///
  /// The statement binds the stored current fingerprint, the next
  /// fingerprint, a strictly increasing generation, and the validity
  /// window; `hostIdentity` must hold the `.host` role (role separation,
  /// ADR §7). Producing a statement does **not** advance local state —
  /// activation is a separate ``apply(_:hostPublicKeyX963:atEpochSeconds:)``
  /// after delivery (two-phase rotation).
  public func makeRotationStatement(
    nextSPKIFingerprint: Data,
    validityStartEpochSeconds: UInt64,
    validityEndEpochSeconds: UInt64,
    hostIdentity: BridgeIdentity
  ) throws -> SignedTLSRotationStatement {
    guard hostIdentity.role == .host else {
      throw TLSRotationStateError.wrongIdentityRole
    }
    lock.lock()
    defer { lock.unlock() }
    guard let state else {
      throw TLSRotationStateError.stateMissing
    }
    guard state.rotationGeneration < UInt64.max else {
      throw TLSRotationStateError.generationOverflow
    }
    let statement = try SecureRotationStatement(
      rotationGeneration: state.rotationGeneration + 1,
      currentSPKIFingerprint: state.currentSPKIFingerprint,
      nextSPKIFingerprint: nextSPKIFingerprint,
      validityStartEpochSeconds: validityStartEpochSeconds,
      validityEndEpochSeconds: validityEndEpochSeconds
    )
    let signature = try hostIdentity.signStatement(statement.canonicalEncoding())
    return SignedTLSRotationStatement(statement: statement, signature: signature)
  }

  /// Verifies `signed` against the stored anti-rollback state and, only
  /// on success, persists and returns the advanced state.
  ///
  /// Verification is `SecureRotationVerifier`'s fixed fail-closed order:
  /// host signature over the canonical bytes, current-pin binding, strict
  /// generation monotonicity above the persisted generation (refusing
  /// rollback and replay), then the validity window at the injected time.
  /// The advanced state persists before it becomes visible; a storage
  /// failure leaves the previous state authoritative.
  @discardableResult
  public func apply(
    _ signed: SignedTLSRotationStatement,
    hostPublicKeyX963: Data,
    atEpochSeconds now: UInt64
  ) throws -> TLSRotationState {
    lock.lock()
    defer { lock.unlock() }
    guard let state else {
      throw TLSRotationStateError.stateMissing
    }
    let hostPublicKey = try SecureP256KeyEncoding.signingPublicKey(
      fromX963: hostPublicKeyX963)
    try SecureRotationVerifier.verify(
      statement: signed.statement,
      signature: signed.signature,
      hostPublicKey: hostPublicKey,
      pinnedCurrentSPKIFingerprint: state.currentSPKIFingerprint,
      lastAcceptedGeneration: state.rotationGeneration,
      atEpochSeconds: now
    )
    let advanced = try TLSRotationState(
      rotationGeneration: signed.statement.rotationGeneration,
      currentSPKIFingerprint: signed.statement.nextSPKIFingerprint,
      previousSPKIFingerprint: signed.statement.currentSPKIFingerprint
    )
    try persist(advanced)
    return advanced
  }

  /// Validates that the live TLS identity still matches the recorded
  /// current SPKI fingerprint.
  ///
  /// A mismatch means the pinned identity was lost or substituted:
  /// ``TLSRotationStateError/identityLost`` surfaces and callers must
  /// disable LAN; recovery requires explicit reset plus re-pairing. Absent
  /// state fails with ``TLSRotationStateError/stateMissing``.
  public func validateIdentityContinuity(currentSPKIFingerprint: Data) throws {
    lock.lock()
    defer { lock.unlock() }
    guard let state else {
      throw TLSRotationStateError.stateMissing
    }
    guard constantTimeEquals(state.currentSPKIFingerprint, currentSPKIFingerprint) else {
      throw TLSRotationStateError.identityLost
    }
  }

  private func persist(_ newState: TLSRotationState) throws {
    try storage.writeBlob(TLSRotationStateBlobCodec.encode(newState))
    state = newState
  }
}
