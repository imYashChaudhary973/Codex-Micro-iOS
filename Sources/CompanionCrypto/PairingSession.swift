import CompanionProtocol
import CryptoKit
import Foundation

/// Closed pairing failure vocabulary shared by both endpoints.
///
/// Every case is a compile-time constant: no case carries wire content, key
/// material, secret-derived data, endpoint text, or a free-form string.
public enum PairingClosedReason: String, Error, Equatable, CaseIterable, Sendable {
  /// No pairing session exists for the presented identifier.
  case unknownPairingSession
  /// The session reached or passed its expiry instant.
  case sessionExpired
  /// The Mac user cancelled the session.
  case sessionCancelled
  /// The single-use bootstrap secret was already claimed and spent, whether
  /// the earlier attempt eventually succeeded or failed.
  case secretAlreadyConsumed
  /// Another claimant won the atomic `available → claimed` transition and its
  /// attempt is still in flight.
  case sessionAlreadyClaimed
  /// The bounded per-session failed-claim budget is exhausted; the session is
  /// destroyed.
  case attemptLimitExceeded
  /// The presented bootstrap secret does not match in constant time.
  case bootstrapSecretMismatch
  /// The pairing mode is not the supported direct-LAN mode.
  case modeUnsupported
  /// The presented endpoint origin does not normalize to the session's.
  case endpointOriginMismatch
  /// The presented protocol selection is not exactly the accepted selection.
  case selectionRejected
  /// A later message references a different pairing session.
  case pairingSessionMismatch
  /// The request is not representable as a canonical pairing transcript.
  case malformedRequest
  /// The presented device public key is not a valid X9.63 P-256 point.
  case deviceKeyInvalid
  /// A second confirmation asserted a different device identifier.
  case deviceIdentityMismatch
  /// The presented host public key does not match the pinned host identity.
  case hostIdentityMismatch
  /// The injected host signer produced no usable 64-byte signature.
  case hostSignatureUnavailable
  /// The host transcript signature does not verify.
  case hostSignatureInvalid
  /// The injected device signer produced no usable 64-byte signature.
  case deviceSignatureUnavailable
  /// The device transcript signature does not verify.
  case deviceSignatureInvalid
  /// The confirmed verification phrase differs from the derived one.
  case verificationPhraseMismatch
  /// The operation requires a claimed session with a bound transcript.
  case sessionNotClaimed
  /// The injected randomness source did not deliver the requested bytes.
  case entropyUnavailable
}

/// Fixed pairing policy values (plan §9).
public enum PairingPolicy {
  /// Exact lifetime of a pairing session in seconds. A session created at
  /// monotonic second `t` is expired at `t + 300`, inclusive of the boundary.
  public static let sessionLifetimeSeconds: UInt64 = 300
  /// How long an expired record is kept as a zeroed tombstone so the closed
  /// rejection reason stays exact, before ``PairingCoordinator/sweepExpired()``
  /// removes it entirely. Secrets are cleared at expiry, not at removal.
  public static let expiredRecordRetentionSeconds: UInt64 = 300
  /// Exact bootstrap-secret size in bytes (256 CSPRNG bits).
  public static let bootstrapSecretByteCount = SecureTransportLimits.bootstrapSecretByteCount
  /// Exact pairing nonce size in bytes (256 random bits each).
  public static let nonceByteCount = SecureTransportLimits.nonceByteCount
  /// Bounded number of failed claim attempts a single session tolerates
  /// before it is destroyed. Per-source transport rate limiting (ADR §9) is
  /// separate and belongs to the listener.
  public static let maxFailedClaimAttempts = 5
}

// MARK: - Injectable seams

/// Cryptographically secure randomness seam.
public protocol PairingRandomSource: Sendable {
  /// Returns exactly `count` fresh random bytes, or throws.
  func randomBytes(count: Int) throws -> Data
}

/// Production CSPRNG source backed by CryptoKit's system randomness.
public struct SystemPairingRandomSource: PairingRandomSource {
  public init() {}

  public func randomBytes(count: Int) throws -> Data {
    guard count > 0, count.isMultiple(of: 8) else {
      throw PairingClosedReason.entropyUnavailable
    }
    let key = SymmetricKey(size: SymmetricKeySize(bitCount: count * 8))
    return key.withUnsafeBytes { Data($0) }
  }
}

/// Monotonic, non-adjustable time source used to enforce pairing expiry.
///
/// Expiry must not be extendable by a wall-clock step (NTP correction,
/// manual change, VM snapshot restore), so the coordinator enforces the
/// five-minute lifetime against this source and uses the wall clock only for
/// the `expiresAt` value the QR displays.
public enum PairingMonotonicClock {
  private static let origin = ContinuousClock.now

  /// Whole seconds elapsed on a monotonic system clock that also advances
  /// while the machine is asleep. It never moves backwards and is unaffected
  /// by wall-clock adjustments.
  public static let system: @Sendable () -> UInt64 = {
    UInt64(max(0, (ContinuousClock.now - origin).components.seconds))
  }
}

/// Long-term identity signing seam over canonical pairing-transcript bytes.
///
/// The Mac's real signer is the Secure Enclave-backed identity in
/// `MacBridgeServer` and the device's is its own Secure Enclave key; neither
/// is imported here, so this module never holds private key material.
public protocol PairingTranscriptSigner: Sendable {
  /// Signs canonical transcript bytes, returning exactly 64 raw `r||s` bytes.
  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data
}

/// Storage seam for ephemeral pairing sessions.
///
/// Sessions are memory-only by contract (threat model §3.3): the bootstrap
/// secret is never persisted to disk.
///
/// **Atomicity contract.** Every state decision — including the
/// `available → claimed` transition, the constant-time secret comparison that
/// guards it, and every confirmation write — happens inside
/// ``withRecord(_:_:)``, whose body must run under the store's own mutual
/// exclusion. Actor isolation alone is not sufficient: several coordinators
/// may share one store (one per connection in the listener), so read, check,
/// and commit must be indivisible **at the store**, not at the caller.
/// Implementations must be thread-safe, and the body never calls back into
/// the store.
public protocol PairingSessionStore: Sendable {
  /// Reads a snapshot of the record for a pairing session, if one exists.
  func record(for pairingSessionID: UUID) -> PairingSessionRecord?

  /// Inserts a new record.
  func insert(_ record: PairingSessionRecord)

  /// Applies `body` to the stored record under the store's mutual exclusion
  /// and commits the result, returning the committed record. Returns `nil`
  /// when no record exists, leaving the store untouched.
  @discardableResult
  func withRecord(
    _ pairingSessionID: UUID,
    _ body: (inout PairingSessionRecord) -> Void
  ) -> PairingSessionRecord?

  /// Clears secret material from every record that reached its monotonic
  /// expiry and removes those that also passed `retentionSeconds` beyond it.
  /// Returns the number of removed records.
  @discardableResult
  func sweep(atMonotonicSeconds now: UInt64, retentionSeconds: UInt64) -> Int
}

/// Default memory-only pairing-session store.
///
/// Pairing sessions are ephemeral and are intentionally never written to
/// disk; a bridge restart cancels every pending pairing. One lock covers
/// every operation, so the compare-and-swap contract above holds even when
/// several coordinators share one store.
public final class InMemoryPairingSessionStore: PairingSessionStore, @unchecked Sendable {
  private let lock = NSLock()
  private var records: [UUID: PairingSessionRecord] = [:]

  public init() {}

  public func record(for pairingSessionID: UUID) -> PairingSessionRecord? {
    lock.lock()
    defer { lock.unlock() }
    return records[pairingSessionID]
  }

  public func insert(_ record: PairingSessionRecord) {
    lock.lock()
    defer { lock.unlock() }
    records[record.pairingSessionID] = record
  }

  @discardableResult
  public func withRecord(
    _ pairingSessionID: UUID,
    _ body: (inout PairingSessionRecord) -> Void
  ) -> PairingSessionRecord? {
    lock.lock()
    defer { lock.unlock() }
    guard var record = records[pairingSessionID] else { return nil }
    body(&record)
    records[pairingSessionID] = record
    return record
  }

  @discardableResult
  public func sweep(atMonotonicSeconds now: UInt64, retentionSeconds: UInt64) -> Int {
    lock.lock()
    defer { lock.unlock() }
    var removed = 0
    for (id, stored) in records {
      guard now >= stored.expiresAtMonotonicSeconds else { continue }
      var record = stored
      if record.holdsLiveSecret {
        record.terminate(.destroyed(.sessionExpired))
        records[id] = record
      }
      if now - record.expiresAtMonotonicSeconds >= retentionSeconds {
        records.removeValue(forKey: id)
        removed += 1
      }
    }
    return removed
  }
}

// MARK: - Session state

/// Lifecycle of one pairing session.
public enum PairingSessionState: Equatable, Sendable {
  /// Created and advertised; the bootstrap secret is unclaimed.
  case available
  /// Atomically claimed. The secret is spent and one attempt is in flight.
  case claimed
  /// The claimed attempt reached a terminal outcome, successful or not. The
  /// secret can never be claimed again.
  case consumed
  /// The session was destroyed for the given closed reason.
  case destroyed(PairingClosedReason)
}

/// One ephemeral pairing session.
///
/// The bootstrap secret lives here only while it can still contribute to a
/// transcript; every terminal transition — completion, failure, cancellation,
/// expiry, or the sweep — clears it along with the host nonce and transcript.
///
/// Expiry is stored twice on purpose: `expiresAtMonotonicSeconds` is the
/// authority the coordinator enforces, and `expiresAtEpochSeconds` exists
/// only so the QR can display a wall-clock instant.
public struct PairingSessionRecord: Equatable, Sendable {
  public let pairingSessionID: UUID
  public let endpointOrigin: PairingEndpointOrigin
  public let selection: SecureProtocolSelection
  public let tlsSPKIFingerprint: Data
  /// Display-only creation instant.
  public let createdAtEpochSeconds: UInt64
  /// Display-only expiry instant, carried by the QR payload.
  public let expiresAtEpochSeconds: UInt64
  /// The enforced expiry, on a monotonic source no clock change can move.
  public let expiresAtMonotonicSeconds: UInt64
  public internal(set) var state: PairingSessionState
  public internal(set) var failedClaimAttempts: Int
  /// Whether the Mac user confirmed the derived verification phrase locally.
  public internal(set) var hostConfirmed: Bool
  /// Whether the device signalled its own local confirmation.
  public internal(set) var deviceConfirmed: Bool
  var bootstrapSecret: Data
  var hostNonce: Data
  var transcript: PairingTranscript?
  var deviceID: UUID?

  init(
    pairingSessionID: UUID,
    endpointOrigin: PairingEndpointOrigin,
    selection: SecureProtocolSelection,
    tlsSPKIFingerprint: Data,
    createdAtEpochSeconds: UInt64,
    expiresAtEpochSeconds: UInt64,
    expiresAtMonotonicSeconds: UInt64,
    bootstrapSecret: Data,
    hostNonce: Data
  ) {
    self.pairingSessionID = pairingSessionID
    self.endpointOrigin = endpointOrigin
    self.selection = selection
    self.tlsSPKIFingerprint = tlsSPKIFingerprint
    self.createdAtEpochSeconds = createdAtEpochSeconds
    self.expiresAtEpochSeconds = expiresAtEpochSeconds
    self.expiresAtMonotonicSeconds = expiresAtMonotonicSeconds
    self.state = .available
    self.failedClaimAttempts = 0
    self.hostConfirmed = false
    self.deviceConfirmed = false
    self.bootstrapSecret = bootstrapSecret
    self.hostNonce = hostNonce
    self.transcript = nil
    self.deviceID = nil
  }

  /// Whether the record still holds material the sweep must clear.
  var holdsLiveSecret: Bool {
    switch state {
    case .available, .claimed: return true
    case .consumed, .destroyed: return false
    }
  }

  /// Moves the record to a terminal state and clears the secret material it
  /// no longer needs.
  mutating func terminate(_ state: PairingSessionState) {
    self.state = state
    bootstrapSecret = Data()
    hostNonce = Data()
    transcript = nil
  }
}

extension PairingSessionRecord: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the record holds the live bootstrap secret and transcript.
  public var description: String { "PairingSessionRecord(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

// MARK: - Pairing outcome

/// Crypto-local capability vocabulary for the initial grant intent.
///
/// `CompanionCrypto` must not depend on `MacBridgeCore`, so pairing states
/// its intent in its own closed vocabulary; the Mac assembly maps `observe`
/// onto the authoritative `view` capability and the `observe` mobile action
/// profile when it calls `DeviceGrantAuthority.addGrant`.
public enum PairedDeviceCapabilityIntent: String, Equatable, CaseIterable, Sendable {
  case observe
}

/// The explicit initial grant intent produced by successful pairing.
///
/// Only ``initial`` is constructible, so pairing can never propose anything
/// beyond `observe` with an empty project allowlist (plan §2 invariant 4).
public struct PairedDeviceGrantIntent: Equatable, Sendable {
  /// Observe capability with an empty project allowlist.
  public static let initial = PairedDeviceGrantIntent(
    capabilities: [.observe], projectAllowlist: [])

  public let capabilities: Set<PairedDeviceCapabilityIntent>
  public let projectAllowlist: Set<String>

  private init(capabilities: Set<PairedDeviceCapabilityIntent>, projectAllowlist: Set<String>) {
    self.capabilities = capabilities
    self.projectAllowlist = projectAllowlist
  }
}

/// The only successful pairing output: a proposal the Mac assembly turns into
/// a stored grant. Pairing itself stores nothing.
public struct PairedDeviceProposal: Equatable, Sendable {
  public let pairingSessionID: UUID
  public let deviceID: UUID
  /// The device's long-term X9.63 public key, validated during pairing.
  public let devicePublicKeyX963: Data
  /// Always ``PairedDeviceGrantIntent/initial``.
  public let initialGrant: PairedDeviceGrantIntent
  public let pairedAtEpochSeconds: UInt64
}

/// Progress after one local confirmation is recorded.
public enum PairingProgress: Equatable, Sendable {
  /// Exactly one side has confirmed; nothing is completed and no proposal
  /// exists yet.
  case awaitingConfirmation
  /// Both sides confirmed; pairing completed with this proposal.
  case completed(PairedDeviceProposal)
}

/// Constant-time equality over fixed-length secrets and digests.
///
/// Every byte pair is combined; the loop has no early exit, so the number of
/// comparisons depends only on the length. Length inequality is not secret —
/// every pairing secret has a fixed size validated by the wire schema.
///
/// - Parameter probe: Internal test seam invoked once per compared byte so a
///   regression that adds an early return fails a test. Production callers
///   omit it and the behaviour is unchanged.
func constantTimeEquals(_ lhs: Data, _ rhs: Data, probe: ((Int) -> Void)? = nil) -> Bool {
  guard lhs.count == rhs.count else { return false }
  var difference: UInt8 = 0
  for (index, pair) in zip(lhs, rhs).enumerated() {
    difference |= pair.0 ^ pair.1
    probe?(index)
  }
  return difference == 0
}
