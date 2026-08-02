import CompanionProtocol
import CryptoKit
import Foundation

/// The device's long-term pairing identity: its non-secret identifier, its
/// X9.63 public key, and the signer that holds the matching private key.
public struct PairingDeviceIdentity: Sendable {
  public let deviceID: UUID
  public let publicKeyX963: Data
  public let signer: any PairingTranscriptSigner

  public init(deviceID: UUID, publicKeyX963: Data, signer: any PairingTranscriptSigner) throws {
    _ = try SecureP256KeyEncoding.signingPublicKey(fromX963: publicKeyX963)
    self.deviceID = deviceID
    self.publicKeyX963 = publicKeyX963
    self.signer = signer
  }
}

/// Device-side pairing choreography, mirroring ``PairingCoordinator``.
///
/// This is the reference implementation the deterministic tests and the Step
/// 2.14 acceptance host use. It is deliberately transport-free and holds no
/// key material of its own; the iOS product client is Phase 3 work.
///
/// The device verifies before it trusts anything: the response must come from
/// the pinned host identity in the QR, its signature must verify over the
/// independently reconstructed transcript, and the transcript-bound
/// verification phrase must be confirmed by the device's own user before the
/// device signs the same transcript back.
public struct PairingDeviceEndpoint: Sendable {
  private let identity: PairingDeviceIdentity
  private let random: any PairingRandomSource
  private let clock: @Sendable () -> UInt64

  public init(
    identity: PairingDeviceIdentity,
    random: any PairingRandomSource = SystemPairingRandomSource(),
    clock: @escaping @Sendable () -> UInt64 = {
      UInt64(max(0, Date().timeIntervalSince1970.rounded(.down)))
    }
  ) {
    self.identity = identity
    self.random = random
    self.clock = clock
  }

  /// Builds the first pairing message from a scanned QR payload.
  ///
  /// The device mints its own 256-bit nonce and echoes the QR's normalized
  /// endpoint origin, exact selection, and one-time secret. An already
  /// expired payload is refused before anything is sent.
  public func beginPairing(with payload: PairingQRPayload) throws -> PairingDeviceAttempt {
    guard clock() < payload.expiresAtEpochSeconds else {
      throw PairingClosedReason.sessionExpired
    }
    guard (try? SecureProtocolNegotiation.accept(payload.selection)) != nil else {
      throw PairingClosedReason.selectionRejected
    }
    guard let nonce = try? random.randomBytes(count: PairingPolicy.nonceByteCount),
      nonce.count == PairingPolicy.nonceByteCount
    else {
      throw PairingClosedReason.entropyUnavailable
    }
    let request = try SecurePairingRequest(
      pairingSessionID: payload.pairingSessionID,
      mode: .directLAN,
      endpointOrigin: payload.endpointOrigin.normalized,
      bootstrapSecret: payload.bootstrapSecret,
      deviceNonce: nonce,
      devicePublicKey: identity.publicKeyX963,
      selection: payload.selection
    )
    return PairingDeviceAttempt(
      request: request,
      payload: payload,
      deviceNonce: nonce,
      identity: identity
    )
  }
}

/// One in-flight device pairing attempt, holding the attempt-local nonce that
/// binds the transcript.
public struct PairingDeviceAttempt: Sendable {
  /// The first pairing message to send.
  public let request: SecurePairingRequest
  private let payload: PairingQRPayload
  private let deviceNonce: Data
  private let identity: PairingDeviceIdentity

  init(
    request: SecurePairingRequest,
    payload: PairingQRPayload,
    deviceNonce: Data,
    identity: PairingDeviceIdentity
  ) {
    self.request = request
    self.payload = payload
    self.deviceNonce = deviceNonce
    self.identity = identity
  }

  /// Verifies the host's reply against the pinned QR identity and the
  /// independently reconstructed transcript, then derives the verification
  /// phrase to display.
  public func verifyHostResponse(
    _ response: SecurePairingResponse
  ) throws -> PairingDeviceVerification {
    guard response.pairingSessionID == payload.pairingSessionID else {
      throw PairingClosedReason.pairingSessionMismatch
    }
    guard response.selection == payload.selection else {
      throw PairingClosedReason.selectionRejected
    }
    guard response.hostID == payload.hostID,
      let presented = try? SPKIFingerprint.fingerprint(x963PublicKey: response.hostPublicKey),
      constantTimeEquals(presented, payload.hostIdentityFingerprint),
      let hostPublicKey = try? SecureP256KeyEncoding.signingPublicKey(
        fromX963: response.hostPublicKey)
    else {
      throw PairingClosedReason.hostIdentityMismatch
    }
    let transcript = try PairingTranscript(
      pairingSessionID: payload.pairingSessionID,
      mode: request.mode,
      endpointOrigin: payload.endpointOrigin.normalized,
      selection: payload.selection,
      bootstrapSecret: payload.bootstrapSecret,
      deviceNonce: deviceNonce,
      devicePublicKey: identity.publicKeyX963,
      hostID: payload.hostID,
      hostNonce: response.hostNonce,
      hostPublicKey: response.hostPublicKey,
      hostTLSSPKIFingerprint: payload.tlsSPKIFingerprint
    )
    guard
      SecureTranscriptSignature.isValid(
        response.transcriptSignature,
        for: transcript.canonicalEncoding(),
        publicKey: hostPublicKey
      )
    else {
      throw PairingClosedReason.hostSignatureInvalid
    }
    return PairingDeviceVerification(transcript: transcript, identity: identity)
  }
}

/// A verified host response awaiting the device user's local confirmation.
public struct PairingDeviceVerification: Sendable {
  /// The transcript both endpoints sign.
  public let transcript: PairingTranscript
  /// The phrase the device displays for comparison with the Mac.
  public let verificationPhrase: SecureShortAuthenticationString
  private let identity: PairingDeviceIdentity

  init(transcript: PairingTranscript, identity: PairingDeviceIdentity) {
    self.transcript = transcript
    self.verificationPhrase = SecureShortAuthenticationString.derive(from: transcript)
    self.identity = identity
  }

  /// Records the device user's own local confirmation and signs the
  /// transcript.
  ///
  /// The returned message is the device's confirmation signal: it is produced
  /// only for a matching phrase, so a mismatch or a cancelled comparison
  /// never reaches the host and completes nothing.
  public func confirmLocally(
    matching phrase: SecureShortAuthenticationString
  ) throws -> SecurePairingConfirmation {
    guard phrase == verificationPhrase else {
      throw PairingClosedReason.verificationPhraseMismatch
    }
    guard
      let signature = try? identity.signer.signPairingTranscript(transcript.canonicalEncoding()),
      signature.count == SecureTranscriptSignature.byteCount
    else {
      throw PairingClosedReason.deviceSignatureUnavailable
    }
    return try SecurePairingConfirmation(
      pairingSessionID: transcript.pairingSessionID,
      deviceID: identity.deviceID,
      transcriptSignature: signature
    )
  }
}

extension PairingDeviceVerification: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the verification holds the transcript, which binds the
  /// single-use bootstrap secret.
  public var description: String { "PairingDeviceVerification(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}
