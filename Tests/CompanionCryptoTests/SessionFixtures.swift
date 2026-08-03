import CompanionProtocol
import CryptoKit
import Foundation

@testable import CompanionCrypto

/// Long-term session signer seam backed by a fixed software key.
struct TestSessionSigner: SessionStatementSigner {
  let privateKey: P256.Signing.PrivateKey

  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    try SecureTranscriptSignature.sign(canonicalBytes, using: privateKey)
  }
}

/// Signer seam that fails, modelling an unavailable Secure Enclave key.
struct FailingSessionSigner: SessionStatementSigner {
  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    throw SessionClosedReason.authenticationFailed
  }
}

/// Signer seam that returns a wrong-length signature.
struct ShortSessionSigner: SessionStatementSigner {
  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    Data(repeating: 0x01, count: 63)
  }
}

/// Signer seam that signs message 1 and then fails, modelling a Secure
/// Enclave key that becomes unavailable mid-handshake.
final class SignerFailingAfterFirstUse: SessionStatementSigner, @unchecked Sendable {
  private let lock = NSLock()
  private var used = false

  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    lock.lock()
    let alreadyUsed = used
    used = true
    lock.unlock()
    guard !alreadyUsed else {
      throw SessionClosedReason.deviceSignatureUnavailable
    }
    return try SecureTranscriptSignature.sign(
      canonicalBytes, using: CryptoFixtures.deviceSigningKey)
  }
}

/// Signer seam that signs with a key the peer does not pin.
struct WrongKeySessionSigner: SessionStatementSigner {
  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    try SecureTranscriptSignature.sign(canonicalBytes, using: CryptoFixtures.tlsCurrentKey)
  }
}

/// Deterministic CSPRNG seam whose draws are distinct and reproducible, so
/// two authentications never collide and every session is independent.
///
/// The first byte stays small, which keeps every 32-byte draw a valid P-256
/// scalar; the counter makes each draw unique.
final class CountingRandomSource: PairingRandomSource, @unchecked Sendable {
  private let lock = NSLock()
  private var draw: UInt8

  init(seed: UInt8 = 0) {
    self.draw = seed
  }

  func randomBytes(count: Int) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    draw &+= 1
    return Data((0..<count).map { UInt8((Int($0) &+ Int(draw)) % 200) &+ 1 })
  }
}

/// Authority stub that answers with a snapshot for a different device.
struct MismatchedDeviceAuthority: SessionAuthorityProviding {
  let snapshot: SessionAuthoritySnapshot

  func authoritySnapshot(deviceID: UUID) async throws -> SessionAuthoritySnapshot? {
    snapshot
  }
}

/// Authority stub that keeps answering with one snapshot captured earlier.
///
/// It models the dangerous shape directly: a handshake that suspended across
/// an authorization change and resumes holding a pre-commit snapshot.
struct StaleSnapshotAuthority: SessionAuthorityProviding {
  let snapshot: SessionAuthoritySnapshot

  func authoritySnapshot(deviceID: UUID) async throws -> SessionAuthoritySnapshot? {
    guard deviceID == snapshot.deviceID else { return nil }
    return snapshot
  }
}

/// Authority wrapper that runs a side effect *inside* the authority read, so
/// a test can make a concurrent change land exactly while a coordinator is
/// suspended on `await`.
final class HookedAuthority: SessionAuthorityProviding, @unchecked Sendable {
  private let base: any SessionAuthorityProviding
  private let lock = NSLock()
  private var hooks: [@Sendable () -> Void] = []

  init(base: any SessionAuthorityProviding) {
    self.base = base
  }

  /// Runs `hook` during the next authority read only.
  func onNextRead(_ hook: @escaping @Sendable () -> Void) {
    lock.lock()
    defer { lock.unlock() }
    hooks.append(hook)
  }

  private func takeHook() -> (@Sendable () -> Void)? {
    lock.lock()
    defer { lock.unlock() }
    return hooks.isEmpty ? nil : hooks.removeFirst()
  }

  func authoritySnapshot(deviceID: UUID) async throws -> SessionAuthoritySnapshot? {
    takeHook()?()
    return try await base.authoritySnapshot(deviceID: deviceID)
  }
}

/// Shared deterministic session inputs.
enum SessionFixtures {
  static let hostID = CryptoFixtures.hostID
  static let deviceID = CryptoFixtures.deviceID
  static let secondDeviceID = PairingFixtures.deviceID
  static let thirdDeviceID = PairingFixtures.otherDeviceID
  static let fourthDeviceID = CryptoFixtures.otherUUID
  static let connectionID = CryptoFixtures.connectionID
  static let otherConnectionID = CryptoFixtures.otherConnectionID
  /// Monotonic origin, deliberately unrelated to any wall-clock epoch.
  static let monotonicOrigin: UInt64 = 5_000

  static func authority(
    devices: [UUID] = [SessionFixtures.deviceID],
    grantRevision: UInt64 = 7,
    authorizedViewEpoch: UInt64 = 3,
    hostGeneration: UInt64 = 1,
    remainingLifetimeSeconds: UInt64? = nil,
    grantExpiresAtEpochSeconds: UInt64? = nil
  ) throws -> InMemorySessionAuthority {
    let authority = InMemorySessionAuthority(hostGeneration: hostGeneration)
    for device in devices {
      try authority.setDevice(
        deviceID: device,
        devicePublicKeyX963: CryptoFixtures.devicePublicKeyX963,
        grantRevision: grantRevision,
        authorizedViewEpoch: authorizedViewEpoch,
        remainingLifetimeSeconds: remainingLifetimeSeconds,
        grantExpiresAtEpochSeconds: grantExpiresAtEpochSeconds
      )
    }
    return authority
  }

  static func coordinator(
    authority: any SessionAuthorityProviding,
    signer: (any SessionStatementSigner)? = nil,
    store: (any AuthenticatedSessionStore)? = nil,
    random: (any PairingRandomSource)? = nil,
    monotonicClock: TestPairingClock? = nil,
    tlsSPKIFingerprint: Data? = nil
  ) throws -> SessionCoordinator {
    try SessionCoordinator(
      hostID: hostID,
      hostTLSSPKIFingerprint: tlsSPKIFingerprint ?? CryptoFixtures.tlsCurrentSPKIFingerprint,
      authority: authority,
      signer: signer ?? TestSessionSigner(privateKey: CryptoFixtures.hostSigningKey),
      store: store ?? InMemoryAuthenticatedSessionStore(),
      random: random ?? CountingRandomSource(),
      monotonicClock: (monotonicClock ?? TestPairingClock(monotonicOrigin)).closure
    )
  }

  static func deviceEndpoint(
    deviceID: UUID = SessionFixtures.deviceID,
    signer: (any SessionStatementSigner)? = nil,
    hostID: UUID = SessionFixtures.hostID,
    hostPublicKeyX963: Data? = nil,
    tlsSPKIFingerprint: Data? = nil,
    random: (any PairingRandomSource)? = nil
  ) throws -> SessionDeviceEndpoint {
    try SessionDeviceEndpoint(
      identity: SessionDeviceIdentity(
        deviceID: deviceID,
        publicKeyX963: CryptoFixtures.devicePublicKeyX963,
        signer: signer ?? TestSessionSigner(privateKey: CryptoFixtures.deviceSigningKey)
      ),
      hostID: hostID,
      hostPublicKeyX963: hostPublicKeyX963 ?? CryptoFixtures.hostPublicKeyX963,
      hostTLSSPKIFingerprint: tlsSPKIFingerprint ?? CryptoFixtures.tlsCurrentSPKIFingerprint,
      random: random ?? CountingRandomSource(seed: 40)
    )
  }

  /// Builds message 1 directly, so a test can vary exactly one field — the
  /// selection, the signing key, the signed host, the ephemeral key, the
  /// nonce, or the signature bytes — without the device endpoint.
  static func request(
    deviceID: UUID = SessionFixtures.deviceID,
    selection: SecureProtocolSelection? = nil,
    signedSelection: SecureProtocolSelection? = nil,
    deviceEphemeralPublicKey: Data? = nil,
    deviceNonce: Data = CryptoFixtures.sessionDeviceNonce,
    signedHostID: UUID = SessionFixtures.hostID,
    signingKey: P256.Signing.PrivateKey = CryptoFixtures.deviceSigningKey,
    tamperSignature: ((Data) -> Data)? = nil
  ) throws -> SecureSessionAuthRequest {
    let wire = try selection ?? SessionPolicy.requiredSelection()
    let ephemeral = deviceEphemeralPublicKey ?? CryptoFixtures.clientEphemeralPublicKeyX963
    let statement = try SessionAuthenticationStatement(
      hostID: signedHostID,
      deviceID: deviceID,
      selection: signedSelection ?? wire,
      deviceEphemeralPublicKey: ephemeral,
      deviceNonce: deviceNonce
    )
    let signature = try SecureTranscriptSignature.sign(
      statement.canonicalEncoding(), using: signingKey)
    return try SecureSessionAuthRequest(
      deviceID: deviceID,
      selection: wire,
      deviceEphemeralPublicKey: ephemeral,
      deviceNonce: deviceNonce,
      transcriptSignature: tamperSignature?(signature) ?? signature
    )
  }

  /// Message 3 for an offer, signed by `signingKey` over the transcript the
  /// device reconstructs from its own request and the host's reply.
  static func confirmation(
    for offer: HostSessionOffer,
    request: SecureSessionAuthRequest,
    deviceID: UUID? = nil,
    sessionID: UUID? = nil,
    signingKey: P256.Signing.PrivateKey = CryptoFixtures.deviceSigningKey,
    tlsSPKIFingerprint: Data? = nil,
    tamperSignature: ((Data) -> Data)? = nil
  ) throws -> SecureSessionAuthConfirmation {
    let transcript = try SessionTranscript(
      sessionID: offer.response.sessionID,
      deviceID: request.deviceID,
      selection: offer.response.selection,
      deviceEphemeralPublicKey: request.deviceEphemeralPublicKey,
      deviceNonce: request.deviceNonce,
      hostEphemeralPublicKey: offer.response.hostEphemeralPublicKey,
      hostNonce: offer.response.hostNonce,
      hostTLSSPKIFingerprint: tlsSPKIFingerprint ?? CryptoFixtures.tlsCurrentSPKIFingerprint
    )
    let signature = try SecureTranscriptSignature.sign(
      transcript.canonicalEncoding(), using: signingKey)
    return try SecureSessionAuthConfirmation(
      sessionID: sessionID ?? offer.response.sessionID,
      deviceID: deviceID ?? request.deviceID,
      transcriptSignature: tamperSignature?(signature) ?? signature
    )
  }
}
