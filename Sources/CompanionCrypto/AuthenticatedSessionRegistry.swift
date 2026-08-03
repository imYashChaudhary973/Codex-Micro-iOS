import CompanionProtocol
import Foundation

/// The authentication generation an authenticated session was established
/// under (ADR §16 row 2.6).
///
/// The spike proved this model in isolation; here it is the value every
/// established session records. Advancing it — a listener restart, a global
/// invalidation, or a host-generation change — invalidates every existing
/// session, which must then reauthenticate. It is a fixed-width unsigned
/// 64-bit counter and fails closed before it could wrap (plan §9).
public struct AuthenticationGeneration: Equatable, Comparable, Sendable {
  public let value: UInt64

  public init(value: UInt64) {
    self.value = value
  }

  /// The generation a fresh registry starts at.
  public static let first = AuthenticationGeneration(value: SessionPolicy.firstGenerationValue)

  /// The next generation, or a closed failure at the fixed-width ceiling.
  /// `UInt64.max` is the last assignable value; there is no wrap.
  public func advanced() throws -> AuthenticationGeneration {
    guard value < UInt64.max else {
      throw SessionClosedReason.generationExhausted
    }
    return AuthenticationGeneration(value: value + 1)
  }

  public static func < (lhs: AuthenticationGeneration, rhs: AuthenticationGeneration) -> Bool {
    lhs.value < rhs.value
  }
}

/// The non-secret identity of one authenticated session.
///
/// The session ID is minted fresh per authentication and is also the frame
/// header's connection binding, so it is what makes frames from a previous
/// session unusable on a new one. The connection ID is the transport's own
/// handle, carried so the listener can close exactly the right connection.
public struct AuthenticatedSessionIdentity: Equatable, Hashable, Sendable {
  public let sessionID: UUID
  public let connectionID: UUID
  public let deviceID: UUID

  public init(sessionID: UUID, connectionID: UUID, deviceID: UUID) {
    self.sessionID = sessionID
    self.connectionID = connectionID
    self.deviceID = deviceID
  }
}

/// The registry record of one active authenticated session.
///
/// It holds no key material: keys live only in the sealer/opener the
/// coordinator hands to the caller. Everything here is the authorization
/// context the session was admitted under — including the Mac authority
/// counters, which never travel in cleartext — so a later check can compare
/// it against the current generation and the current Mac authority.
public struct AuthenticatedSessionRecord: Equatable, Sendable {
  public let identity: AuthenticatedSessionIdentity
  public let generation: AuthenticationGeneration
  public let grantRevision: UInt64
  public let authorizedViewEpoch: UInt64
  public let hostGeneration: UInt64
  /// The authority commit sequence this session was admitted under.
  public let authorityCommitSequence: UInt64
  /// Establishment instant on the coordinator's monotonic seam.
  public let establishedAtMonotonicSeconds: UInt64
  /// Monotonic deadline derived once from the grant's remaining lifetime, or
  /// `nil` when the grant carries no expiry. Wall-clock movement — in either
  /// direction — cannot change it.
  public let expiresAtMonotonicSeconds: UInt64?
  /// The grant's wall-clock expiry instant as the Mac reported it, carried
  /// for the Mac's own expiry scheduling. Liveness is never decided from it.
  public let grantExpiresAtEpochSeconds: UInt64?
  /// SHA-256 of the canonical authentication statement that opened this
  /// handshake. Defence in depth only: freshness comes from the device's
  /// signature over the host-contributed transcript, never from this digest.
  public let requestBinding: Data

  /// Records are minted by ``SessionCoordinator`` alone: the memberwise
  /// initializer stays internal so no caller can fabricate an authorization
  /// context.

  /// Whether this session reached its monotonic expiry deadline.
  func isExpired(atMonotonicSeconds now: UInt64) -> Bool {
    guard let expiresAtMonotonicSeconds else { return false }
    return now >= expiresAtMonotonicSeconds
  }

  /// Whether the authority still matches the context this session was
  /// admitted under. A newer grant revision, authorized-view epoch, or host
  /// generation means continued use is denied and the device must
  /// reauthenticate (plan §2 invariant 11).
  func matches(_ snapshot: SessionAuthoritySnapshot) -> Bool {
    snapshot.deviceID == identity.deviceID
      && snapshot.grantRevision == grantRevision
      && snapshot.authorizedViewEpoch == authorizedViewEpoch
      && snapshot.hostGeneration == hostGeneration
  }
}

/// The complete registry state: the current authentication generation, the
/// published authority watermark, the fixed-width latch, and at most one
/// active session per device (plan §2 invariant 18).
public struct AuthenticatedSessionState: Equatable, Sendable {
  public internal(set) var generation: AuthenticationGeneration
  public internal(set) var sessions: [UUID: AuthenticatedSessionRecord]
  /// The highest authority commit sequence any committed authorization
  /// change has published. A handshake whose snapshot predates it is refused
  /// at commit.
  public internal(set) var authorityWatermark: UInt64
  /// Set when the generation reached its fixed-width ceiling. It lives in
  /// the store, not in a coordinator instance, so a fresh coordinator over
  /// the same registry cannot resume authentication at the ceiling.
  public internal(set) var isGenerationExhausted: Bool

  public init(
    generation: AuthenticationGeneration = .first,
    sessions: [UUID: AuthenticatedSessionRecord] = [:],
    authorityWatermark: UInt64 = 0,
    isGenerationExhausted: Bool = false
  ) {
    self.generation = generation
    self.sessions = sessions
    self.authorityWatermark = authorityWatermark
    self.isGenerationExhausted = isGenerationExhausted
  }
}

/// One invalidated session and the closed reason the transport must close it
/// with. Reasons here are always post-authentication, so they are specific.
public struct SessionInvalidation: Equatable, Sendable {
  public let identity: AuthenticatedSessionIdentity
  public let reason: SessionClosedReason

  public init(identity: AuthenticatedSessionIdentity, reason: SessionClosedReason) {
    self.identity = identity
    self.reason = reason
  }
}

/// The outcome of advancing the authentication generation.
public struct GenerationAdvance: Equatable, Sendable {
  /// Every session the advance invalidated. The caller must close all of
  /// them — including when the advance failed closed at the ceiling.
  public let invalidated: [AuthenticatedSessionIdentity]
  /// The generation now in force. Unchanged when ``isExhausted`` is true.
  public let generation: AuthenticationGeneration
  /// True when the fixed-width ceiling was reached: the generation did not
  /// advance, the registry was emptied, and no further authentication is
  /// admitted on this registry.
  public let isExhausted: Bool
}

/// Storage seam for active authenticated sessions.
///
/// Sessions are memory-only by contract: they hold no durable authority and a
/// bridge restart must force reauthentication.
///
/// **Atomicity contract.** Every decision that reads and then writes registry
/// state — the one-active-session replacement, the authority-watermark check,
/// the generation advance, and each invalidation — happens inside
/// ``mutate(_:)``, whose body must run under the store's own mutual
/// exclusion. Actor isolation alone is not sufficient: the listener may hold
/// several coordinators over one store (one per connection), so read, check,
/// and commit must be indivisible **at the store**, not at the caller.
/// Implementations must be thread-safe, and the body never calls back into
/// the store.
public protocol AuthenticatedSessionStore: Sendable {
  /// A snapshot read of the complete registry state.
  func state() -> AuthenticatedSessionState

  /// Applies `body` to the stored state under the store's mutual exclusion,
  /// commits the result, and returns the body's value.
  func mutate<Value>(_ body: (inout AuthenticatedSessionState) -> Value) -> Value
}

/// Default memory-only session registry.
///
/// One lock covers every operation, so the compare-and-swap contract above
/// holds even when several coordinators share one store.
public final class InMemoryAuthenticatedSessionStore: AuthenticatedSessionStore, @unchecked Sendable
{
  private let lock = NSLock()
  private var current: AuthenticatedSessionState

  /// - Parameters:
  ///   - generation: The generation the registry starts at. Tests pin it
  ///     near the fixed-width ceiling to prove the closed overflow
  ///     behaviour; production starts at ``AuthenticationGeneration/first``.
  ///   - authorityWatermark: The highest authority commit sequence already
  ///     published. Production starts at 0 and learns the real value from
  ///     the first authority read.
  public init(
    generation: AuthenticationGeneration = .first,
    authorityWatermark: UInt64 = 0
  ) {
    self.current = AuthenticatedSessionState(
      generation: generation, authorityWatermark: authorityWatermark)
  }

  public func state() -> AuthenticatedSessionState {
    lock.lock()
    defer { lock.unlock() }
    return current
  }

  public func mutate<Value>(_ body: (inout AuthenticatedSessionState) -> Value) -> Value {
    lock.lock()
    defer { lock.unlock() }
    return body(&current)
  }
}
