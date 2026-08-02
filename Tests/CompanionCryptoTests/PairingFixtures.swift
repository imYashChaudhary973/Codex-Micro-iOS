import CompanionProtocol
import CryptoKit
import Foundation

@testable import CompanionCrypto

/// Deterministic clock seam. Tests never sleep; they set the epoch directly.
final class TestPairingClock: @unchecked Sendable {
  private let lock = NSLock()
  private var seconds: UInt64

  init(_ seconds: UInt64) {
    self.seconds = seconds
  }

  var now: UInt64 {
    lock.lock()
    defer { lock.unlock() }
    return seconds
  }

  func set(_ value: UInt64) {
    lock.lock()
    defer { lock.unlock() }
    seconds = value
  }

  func advance(_ delta: UInt64) {
    lock.lock()
    defer { lock.unlock() }
    seconds += delta
  }

  var closure: @Sendable () -> UInt64 {
    { [self] in now }
  }
}

/// Scripted CSPRNG seam that also records every requested byte count.
final class ScriptedRandomSource: PairingRandomSource, @unchecked Sendable {
  private let lock = NSLock()
  private var values: [Data]
  private var recorded: [Int] = []
  private let failure: Bool
  private let truncateTo: Int?

  init(values: [Data], failure: Bool = false, truncateTo: Int? = nil) {
    self.values = values
    self.failure = failure
    self.truncateTo = truncateTo
  }

  var requestedCounts: [Int] {
    lock.lock()
    defer { lock.unlock() }
    return recorded
  }

  func randomBytes(count: Int) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    recorded.append(count)
    if failure {
      throw PairingClosedReason.entropyUnavailable
    }
    if let truncateTo {
      return Data(repeating: 0xAA, count: truncateTo)
    }
    guard !values.isEmpty else {
      return Data(repeating: 0x5A, count: count)
    }
    return values.removeFirst()
  }
}

/// Long-term identity signer seam backed by a fixed software key.
struct TestTranscriptSigner: PairingTranscriptSigner {
  let privateKey: P256.Signing.PrivateKey

  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try SecureTranscriptSignature.sign(canonicalBytes, using: privateKey)
  }
}

/// Signer seam that fails, modelling an unavailable Secure Enclave key.
struct FailingTranscriptSigner: PairingTranscriptSigner {
  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    throw PairingClosedReason.hostSignatureUnavailable
  }
}

/// Signer seam that returns a wrong-length signature.
struct ShortTranscriptSigner: PairingTranscriptSigner {
  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    Data(repeating: 0x01, count: 63)
  }
}

/// Signer seam that signs with the wrong long-term key.
struct WrongKeyTranscriptSigner: PairingTranscriptSigner {
  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try SecureTranscriptSignature.sign(canonicalBytes, using: CryptoFixtures.deviceSigningKey)
  }
}

/// Shared deterministic pairing inputs.
enum PairingFixtures {
  static let epoch: UInt64 = 1_754_000_000
  /// Arbitrary origin for the monotonic seam, deliberately unrelated to the
  /// wall-clock epoch so the two cannot be confused in tests.
  static let monotonicOrigin: UInt64 = 10_000
  /// Scripted CSPRNG draw for the pairing session ID; yields the fixed
  /// `11111111-…` identifier shared with `CryptoFixtures`.
  static let pairingSessionIDBytes = Data(repeating: 0x11, count: 16)
  static let bootstrapSecret = Data(repeating: 0xB5, count: 32)
  static let hostNonce = Data(repeating: 0xE2, count: 32)
  static let deviceNonce = Data(repeating: 0xD1, count: 32)
  static let deviceID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
  static let otherDeviceID = UUID(uuidString: "88888888-8888-8888-8888-888888888888")!

  static func origin(_ raw: String = "wss://192.168.4.20:8443") throws -> PairingEndpointOrigin {
    try PairingEndpointOrigin(raw)
  }

  static func hostRandom() -> ScriptedRandomSource {
    ScriptedRandomSource(values: [pairingSessionIDBytes, bootstrapSecret, hostNonce])
  }

  /// A verification phrase derived from a deliberately different transcript.
  /// The scripted CSPRNG makes the coordinator reproduce the shared
  /// `CryptoFixtures` transcript exactly, so a mismatch must come from a
  /// transcript that genuinely differs.
  static func mismatchedPhrase() throws -> SecureShortAuthenticationString {
    SecureShortAuthenticationString.derive(
      from: try CryptoFixtures.pairingTranscript(hostID: CryptoFixtures.otherUUID))
  }

  static func deviceRandom() -> ScriptedRandomSource {
    ScriptedRandomSource(values: [deviceNonce])
  }

  static func qrPayload(
    selection: SecureProtocolSelection? = nil,
    hostID: UUID = CryptoFixtures.hostID,
    endpointOrigin: PairingEndpointOrigin? = nil,
    hostIdentityFingerprint: Data? = nil,
    tlsSPKIFingerprint: Data? = nil,
    pairingSessionID: UUID = CryptoFixtures.pairingSessionID,
    bootstrapSecret: Data = PairingFixtures.bootstrapSecret,
    expiresAtEpochSeconds: UInt64 = PairingFixtures.epoch + PairingPolicy.sessionLifetimeSeconds
  ) throws -> PairingQRPayload {
    try PairingQRPayload(
      selection: selection ?? CryptoFixtures.selection(),
      hostID: hostID,
      endpointOrigin: endpointOrigin ?? origin(),
      hostIdentityFingerprint: hostIdentityFingerprint
        ?? SPKIFingerprint.fingerprint(of: CryptoFixtures.hostSigningKey.publicKey),
      tlsSPKIFingerprint: tlsSPKIFingerprint ?? CryptoFixtures.tlsCurrentSPKIFingerprint,
      pairingSessionID: pairingSessionID,
      bootstrapSecret: bootstrapSecret,
      expiresAtEpochSeconds: expiresAtEpochSeconds
    )
  }

  /// The request a well-behaved device sends for `payload`.
  static func request(
    for payload: PairingQRPayload,
    mode: SecurePairingMode = .directLAN,
    endpointOrigin: String? = nil,
    bootstrapSecret: Data? = nil,
    deviceNonce: Data = PairingFixtures.deviceNonce,
    devicePublicKey: Data? = nil,
    selection: SecureProtocolSelection? = nil
  ) throws -> SecurePairingRequest {
    try SecurePairingRequest(
      pairingSessionID: payload.pairingSessionID,
      mode: mode,
      endpointOrigin: endpointOrigin ?? payload.endpointOrigin.normalized,
      bootstrapSecret: bootstrapSecret ?? payload.bootstrapSecret,
      deviceNonce: deviceNonce,
      devicePublicKey: devicePublicKey ?? CryptoFixtures.devicePublicKeyX963,
      selection: selection ?? payload.selection
    )
  }
}
