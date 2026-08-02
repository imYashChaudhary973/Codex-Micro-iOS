import Foundation

/// Claim-based lifecycle store for the Mac bridge's long-term identities
/// (ADR §6).
///
/// All lifecycle decisions live here and run identically against the
/// production Secure Enclave backend and the deterministic test backend:
///
/// - **Atomic creation:** an atomic claim is acquired before key creation;
///   post-create validation requires exactly one claim and one matching
///   key, with rollback of both on any failure.
/// - **Strict retrieval:** loading validates claim/key cardinality, the
///   required non-exportable attribute profile, the expected SPKI
///   fingerprint, and asserts export denial — in that order — and fails
///   closed on every violation.
/// - **No silent regeneration:** ``loadOrCreate(role:expectedSPKIFingerprint:)``
///   never replaces existing state, and an expected-but-missing identity
///   surfaces ``BridgeIdentityError/identityLost`` instead of a new key.
///   Replacement happens only through ``reset(role:)``, which the injected
///   policy gates on "no grants exist".
public struct BridgeIdentityStore {
  /// Injected reset gate. Returns `true` only when no device grants exist
  /// and destroying an identity is therefore permitted. A throwing policy
  /// is treated as refusal.
  public typealias ResetPolicy = () throws -> Bool

  private let backend: any SecureIdentityBackend
  private let resetPolicy: ResetPolicy

  /// Creates a store over `backend`, gating ``reset(role:)`` on
  /// `resetPolicy`.
  public init(backend: any SecureIdentityBackend, resetPolicy: @escaping ResetPolicy) {
    self.backend = backend
    self.resetPolicy = resetPolicy
  }

  /// Creates the identity for `role`.
  ///
  /// Creation first inserts the atomic claim; a pre-existing claim maps to
  /// the closed duplicate/incomplete/multiplicity vocabulary without
  /// touching stored keys. After key creation, the new key must validate
  /// its attribute profile, prove export denial, and be the single stored
  /// key under a single claim; any failure rolls back both the key and the
  /// claim before rethrowing.
  public func create(role: BridgeIdentityRole) throws -> BridgeIdentity {
    try backend.withExclusiveCreation {
      switch try backend.insertClaim(for: role) {
      case .alreadyPresent:
        throw try existingStateError(role: role)
      case .inserted:
        break
      }

      var createdKey: (any SecureIdentityKey)?
      do {
        let preexisting = try backend.existingKeys(for: role)
        guard preexisting.isEmpty else {
          throw preexisting.count == 1
            ? BridgeIdentityError.claimMissing
            : BridgeIdentityError.keyMultiplicity(count: preexisting.count)
        }

        let key = try backend.createKey(for: role)
        createdKey = key
        let identity = try BridgeIdentity(role: role, key: key)
        try key.validateRequiredAttributes()
        try key.assertNonExportable()
        try validatePostCreateState(role: role, identity: identity)
        return identity
      } catch {
        try rollback(role: role, key: createdKey)
        throw error
      }
    }
  }

  /// Loads and strictly validates the identity for `role`.
  ///
  /// Validation order is fixed: claim/key cardinality, attribute profile,
  /// public-key extraction, expected SPKI fingerprint (constant-time),
  /// then the export-denial assertion. Every violation fails closed with a
  /// closed reason; nothing on this path mutates stored state.
  public func load(
    role: BridgeIdentityRole,
    expectedSPKIFingerprint: Data? = nil
  ) throws -> BridgeIdentity {
    let claimCount = try backend.claimCount(for: role)
    let keys = try backend.existingKeys(for: role)

    guard claimCount > 0 || !keys.isEmpty else {
      throw BridgeIdentityError.identityMissing
    }
    guard keys.count <= 1 else {
      throw BridgeIdentityError.keyMultiplicity(count: keys.count)
    }
    guard claimCount <= 1 else {
      throw BridgeIdentityError.claimStoreFailure
    }
    guard let key = keys.first else {
      throw BridgeIdentityError.incompleteCreation
    }
    guard claimCount == 1 else {
      throw BridgeIdentityError.claimMissing
    }

    try key.validateRequiredAttributes()
    let identity = try BridgeIdentity(role: role, key: key)
    if let expectedSPKIFingerprint,
      !constantTimeEquals(identity.spkiFingerprint, expectedSPKIFingerprint)
    {
      throw BridgeIdentityError.fingerprintMismatch
    }
    try key.assertNonExportable()
    return identity
  }

  /// Loads the identity for `role`, creating it only when no identity
  /// state exists at all.
  ///
  /// The outcome distinguishes ``BridgeIdentityLoadOutcome/created(_:)``
  /// from ``BridgeIdentityLoadOutcome/existing(_:)``; an existing identity
  /// is **never** replaced. When `expectedSPKIFingerprint` is provided and
  /// no identity exists, the identity was lost and
  /// ``BridgeIdentityError/identityLost`` surfaces instead of a fresh key —
  /// callers must disable LAN and require explicit reset plus re-pairing.
  /// Every other load failure (corrupt, duplicate, mismatched, exportable)
  /// rethrows unchanged without creating anything.
  public func loadOrCreate(
    role: BridgeIdentityRole,
    expectedSPKIFingerprint: Data? = nil
  ) throws -> BridgeIdentityLoadOutcome {
    do {
      return .existing(
        try load(role: role, expectedSPKIFingerprint: expectedSPKIFingerprint))
    } catch BridgeIdentityError.identityMissing {
      guard expectedSPKIFingerprint == nil else {
        throw BridgeIdentityError.identityLost
      }
      return .created(try create(role: role))
    }
  }

  /// Destroys all identity state for `role` after the injected policy
  /// permits it.
  ///
  /// This is the only replacement path: the policy must confirm that no
  /// grants exist (Phase 2 invariant 3), otherwise
  /// ``BridgeIdentityError/resetRefused`` surfaces and nothing changes.
  /// Destruction is verified — residual keys or claims fail closed with
  /// ``BridgeIdentityError/cleanupIncomplete``.
  public func reset(role: BridgeIdentityRole) throws {
    guard (try? resetPolicy()) == true else {
      throw BridgeIdentityError.resetRefused
    }
    try backend.deleteAllKeys(for: role)
    try backend.removeClaim(for: role)
    guard try backend.existingKeys(for: role).isEmpty,
      try backend.claimCount(for: role) == 0
    else {
      throw BridgeIdentityError.cleanupIncomplete
    }
  }

  private func validatePostCreateState(
    role: BridgeIdentityRole,
    identity: BridgeIdentity
  ) throws {
    let keys = try backend.existingKeys(for: role)
    guard keys.count == 1 else {
      throw BridgeIdentityError.keyMultiplicity(count: keys.count)
    }
    guard let stored = try? keys[0].publicKeyX963(),
      constantTimeEquals(stored, identity.publicKeyX963)
    else {
      throw BridgeIdentityError.fingerprintMismatch
    }
    guard try backend.claimCount(for: role) == 1 else {
      throw BridgeIdentityError.claimStoreFailure
    }
  }

  private func existingStateError(role: BridgeIdentityRole) throws -> BridgeIdentityError {
    let keys = try backend.existingKeys(for: role)
    switch keys.count {
    case 0:
      return .incompleteCreation
    case 1:
      return .duplicateIdentity
    default:
      return .keyMultiplicity(count: keys.count)
    }
  }

  private func rollback(role: BridgeIdentityRole, key: (any SecureIdentityKey)?) throws {
    do {
      if let key {
        try backend.deleteKey(key, for: role)
      }
      try backend.removeClaim(for: role)
    } catch {
      throw BridgeIdentityError.rollbackFailure
    }
  }
}
