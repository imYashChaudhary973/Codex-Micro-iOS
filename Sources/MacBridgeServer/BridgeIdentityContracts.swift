import CompanionCrypto
import CryptoKit
import Foundation
import X509

/// Long-term Mac bridge identity roles (ADR §6).
///
/// `.host` signs pairing transcripts and TLS-key rotation statements;
/// `.tls` is the separate key behind the served certificate. The two roles
/// are stored, validated, and destroyed independently and are never
/// interchangeable.
public enum BridgeIdentityRole: String, CaseIterable, Sendable {
  case host
  case tls
}

/// Closed identity-lifecycle failure vocabulary.
///
/// Cases carry no content beyond nonnegative counts: no OSStatus, endpoint,
/// name, path, fingerprint, or key material ever rides on an error (threat
/// model §6, ADR §13).
public enum BridgeIdentityError: Error, Equatable, Sendable {
  /// Stored key attributes do not match the required non-exportable
  /// Secure Enclave profile.
  case attributeMismatch
  /// A stored key exists without its creation claim (corrupt claim state).
  case claimMissing
  /// Claim bookkeeping is unreadable, unwritable, or internally
  /// inconsistent (including duplicate claims).
  case claimStoreFailure
  /// The Keychain refused for lack of an entitlement.
  ///
  /// Distinct from ``claimStoreFailure`` because the fix is completely
  /// different: the Data Protection Keychain requires the calling code to
  /// carry an `application-identifier` entitlement, which comes from signing
  /// with a provisioning profile. A bundle signed with a bare identity gets
  /// `errSecMissingEntitlement` on every write, which is a packaging problem
  /// and not a broken Keychain — collapsing the two sends whoever reads it
  /// looking in the wrong place.
  case entitlementMissing
  /// Verified destruction left residual key or claim state behind.
  case cleanupIncomplete
  /// A complete identity already exists; creation never replaces it.
  case duplicateIdentity
  /// The loaded key's SPKI fingerprint differs from the caller's
  /// expectation. Callers must fail closed.
  case fingerprintMismatch
  /// An identity the caller expected to exist is gone. Callers must treat
  /// this as identity loss and disable LAN (Phase 2 invariant 3); no
  /// replacement is ever created on this path.
  case identityLost
  /// No identity state exists for the role.
  case identityMissing
  /// A creation claim exists without a stored key.
  case incompleteCreation
  /// More than one stored key matched the role.
  case keyMultiplicity(count: Int)
  /// The key store is unavailable, unwritable, or returned malformed data.
  case keyStoreFailure
  /// The private key material was exportable by this process. The identity
  /// is unusable; software keys are rejected outright (ADR §3/§6).
  case privateKeyExportable
  /// The public key could not be derived or was malformed.
  case publicKeyUnavailable
  /// Reset was requested while the injected policy reports that grants
  /// still exist (or the policy itself failed).
  case resetRefused
  /// Rolling back an incomplete creation failed; residual state may exist.
  case rollbackFailure
  /// Producing a signature failed.
  case signatureFailure
}

/// Outcome of inserting a creation claim.
public enum BridgeClaimInsertion: Equatable, Sendable {
  /// The claim was newly inserted; the caller owns creation.
  case inserted
  /// A claim already existed; another creation won or state is stale.
  case alreadyPresent
}

/// One stored private key as seen through a ``SecureIdentityBackend``.
///
/// The production implementation wraps a Secure Enclave `SecKey`; the test
/// implementation wraps a deterministic in-memory CryptoKit key behind the
/// same contract. Every method throws only ``BridgeIdentityError`` cases.
/// Implementations must be safe to use from multiple threads.
public protocol SecureIdentityKey: AnyObject {
  /// The 65-byte X9.63 uncompressed P-256 public key.
  func publicKeyX963() throws -> Data

  /// Signs `message` with ECDSA P-256/SHA-256, returning exactly 64 raw
  /// `r||s` bytes (ADR §11).
  func signRaw(_ message: Data) throws -> Data

  /// Throws unless the stored attributes match the required profile:
  /// private P-256 key, Secure Enclave resident, non-extractable
  /// (``BridgeIdentityError/attributeMismatch`` otherwise).
  func validateRequiredAttributes() throws

  /// Throws ``BridgeIdentityError/privateKeyExportable`` if this process
  /// can export the private key material.
  func assertNonExportable() throws

  /// An X509 signer over this key for certificate issuance. Production
  /// signs through the non-exportable `SecKey`; tests sign with CryptoKit.
  func certificateSigner() throws -> Certificate.PrivateKey
}

/// Storage seam for long-term identity keys and their creation claims.
///
/// ``BridgeIdentityStore`` owns all lifecycle logic (claim ordering,
/// rollback, validation ordering, fail-closed decisions); implementations
/// of this protocol only move bytes. The production backend is the Data
/// Protection Keychain plus Secure Enclave; the deterministic test fake is
/// an in-memory table with injectable failures. Every method throws only
/// ``BridgeIdentityError`` cases.
public protocol SecureIdentityBackend: AnyObject {
  /// Atomically inserts the creation claim for `role`.
  func insertClaim(for role: BridgeIdentityRole) throws -> BridgeClaimInsertion

  /// The number of stored claims for `role` (0 when absent).
  func claimCount(for role: BridgeIdentityRole) throws -> Int

  /// Removes the claim for `role`; absent claims are not an error.
  func removeClaim(for role: BridgeIdentityRole) throws

  /// Creates and stores a new private key for `role`.
  func createKey(for role: BridgeIdentityRole) throws -> any SecureIdentityKey

  /// Every stored key matching `role` (empty when none exist).
  func existingKeys(for role: BridgeIdentityRole) throws -> [any SecureIdentityKey]

  /// Deletes exactly `key`; an already-deleted key is not an error.
  func deleteKey(_ key: any SecureIdentityKey, for role: BridgeIdentityRole) throws

  /// Deletes every stored key for `role`; absent keys are not an error.
  func deleteAllKeys(for role: BridgeIdentityRole) throws

  /// Serializes creation attempts within this process.
  func withExclusiveCreation<T>(_ body: () throws -> T) rethrows -> T
}

/// A loaded long-term identity: role, validated public key material, and a
/// handle to the non-exportable private key.
///
/// Thread-safety: the wrapped key must be safe for concurrent use, which
/// the Secure Enclave `SecKey` backend guarantees.
public struct BridgeIdentity: @unchecked Sendable {
  /// The stored role this identity was created and validated for.
  public let role: BridgeIdentityRole
  /// The 65-byte X9.63 uncompressed P-256 public key.
  public let publicKeyX963: Data
  /// The P-256 SubjectPublicKeyInfo DER of the public key.
  public let spkiDER: Data
  /// The SHA-256 SPKI fingerprint clients pin (ADR §7).
  public let spkiFingerprint: Data

  let key: any SecureIdentityKey

  init(role: BridgeIdentityRole, key: any SecureIdentityKey) throws {
    let x963 = try key.publicKeyX963()
    guard let spkiDER = try? SPKIFingerprint.subjectPublicKeyInfoDER(x963PublicKey: x963) else {
      throw BridgeIdentityError.publicKeyUnavailable
    }
    self.role = role
    self.publicKeyX963 = x963
    self.spkiDER = spkiDER
    self.spkiFingerprint = Data(SHA256.hash(data: spkiDER))
    self.key = key
  }

  /// The CryptoKit public key for signature verification.
  public func publicSigningKey() throws -> P256.Signing.PublicKey {
    guard let key = try? SecureP256KeyEncoding.signingPublicKey(fromX963: publicKeyX963) else {
      throw BridgeIdentityError.publicKeyUnavailable
    }
    return key
  }

  /// Signs canonical statement bytes, returning exactly 64 raw `r||s`
  /// bytes. Any malformed backend signature fails closed.
  public func signStatement(_ canonicalBytes: Data) throws -> Data {
    let signature = try key.signRaw(canonicalBytes)
    guard signature.count == 64 else {
      throw BridgeIdentityError.signatureFailure
    }
    return signature
  }

  func certificateSigner() throws -> Certificate.PrivateKey {
    try key.certificateSigner()
  }
}

/// Distinguishes a freshly created identity from a pre-existing one.
/// ``BridgeIdentityStore/loadOrCreate(role:expectedSPKIFingerprint:)``
/// never converts one into the other.
public enum BridgeIdentityLoadOutcome {
  /// No identity existed and a new one was created.
  case created(BridgeIdentity)
  /// The stored identity was loaded and validated; it was not replaced.
  case existing(BridgeIdentity)

  /// The loaded or created identity.
  public var identity: BridgeIdentity {
    switch self {
    case .created(let identity), .existing(let identity):
      return identity
    }
  }
}

/// Constant-time equality over fixed-length digests and fingerprints.
func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
  guard lhs.count == rhs.count else { return false }
  var difference: UInt8 = 0
  for (left, right) in zip(lhs, rhs) {
    difference |= left ^ right
  }
  return difference == 0
}
