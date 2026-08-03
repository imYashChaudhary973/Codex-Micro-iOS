import CompanionProtocol
import CryptoKit
import Foundation

/// The device's long-term session identity: its non-secret identifier, its
/// X9.63 public key, and the signer that holds the matching private key.
public struct SessionDeviceIdentity: Sendable {
  public let deviceID: UUID
  public let publicKeyX963: Data
  public let signer: any SessionStatementSigner

  public init(deviceID: UUID, publicKeyX963: Data, signer: any SessionStatementSigner) throws {
    guard (try? SecureP256KeyEncoding.signingPublicKey(fromX963: publicKeyX963)) != nil else {
      throw SessionClosedReason.deviceKeyInvalid
    }
    self.deviceID = deviceID
    self.publicKeyX963 = publicKeyX963
    self.signer = signer
  }
}

/// One established device-side session, mirroring ``EstablishedHostSession``
/// with the directions swapped.
///
/// It carries no authority counter: the Mac's grant revision, authorized-view
/// epoch, and host generation are host-side state and reach the device only
/// in sealed post-authentication traffic (Step 2.8).
public struct EstablishedDeviceSession: Sendable {
  public let sessionID: UUID
  public let deviceID: UUID
  /// The transcript the device reconstructed, verified, and signed.
  public let transcript: SessionTranscript
  /// Seals client-to-server frames.
  public var outbound: SecureFrameSealer
  /// Opens server-to-client frames.
  public var inbound: SecureFrameOpener
}

extension EstablishedDeviceSession: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the session holds both directional frame keys.
  public var description: String { "EstablishedDeviceSession(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// The device's completion of a handshake: message 3 plus the session it
/// establishes locally once the host accepts that message.
public struct DeviceSessionCompletion: Sendable {
  /// The confirmation message to send.
  public let confirmation: SecureSessionAuthConfirmation
  /// The device's own established session.
  public let session: EstablishedDeviceSession
}

extension DeviceSessionCompletion: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: it carries the established session's directional keys.
  public var description: String { "DeviceSessionCompletion(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// Device-side session choreography, mirroring ``SessionCoordinator``.
///
/// This is the reference implementation the deterministic tests and the Step
/// 2.14 acceptance host use. It is deliberately transport-free and holds no
/// key material of its own; the iOS product client is Phase 3 work.
///
/// The device verifies before it trusts anything: the reply must echo the
/// exact negotiated tuple, and its signature must verify against the host
/// identity pinned at pairing over a transcript the device reconstructs
/// itself — including the TLS SPKI fingerprint it has pinned, so a session
/// offered under a different channel identity fails closed. Only then does
/// the device sign the same transcript back and derive frame keys.
public struct SessionDeviceEndpoint: Sendable {
  private let identity: SessionDeviceIdentity
  private let hostID: UUID
  private let hostPublicKeyX963: Data
  private let hostTLSSPKIFingerprint: Data
  private let random: any PairingRandomSource

  /// - Parameters:
  ///   - identity: The device's long-term identity and signer.
  ///   - hostID: The opaque host identifier learned at pairing.
  ///   - hostPublicKeyX963: The long-term host identity key pinned at
  ///     pairing; the only key a host reply is ever verified against.
  ///   - hostTLSSPKIFingerprint: The TLS SPKI fingerprint the device has
  ///     pinned, from pairing or a verified rotation statement.
  ///   - random: CSPRNG seam.
  public init(
    identity: SessionDeviceIdentity,
    hostID: UUID,
    hostPublicKeyX963: Data,
    hostTLSSPKIFingerprint: Data,
    random: any PairingRandomSource = SystemPairingRandomSource()
  ) throws {
    guard (try? SecureP256KeyEncoding.signingPublicKey(fromX963: hostPublicKeyX963)) != nil else {
      throw SessionClosedReason.deviceKeyInvalid
    }
    try requireExactCryptoByteCount(
      hostTLSSPKIFingerprint, SPKIFingerprint.byteCount, field: "hostTLSSPKIFingerprint")
    self.identity = identity
    self.hostID = hostID
    self.hostPublicKeyX963 = hostPublicKeyX963
    self.hostTLSSPKIFingerprint = hostTLSSPKIFingerprint
    self.random = random
  }

  /// Builds message 1.
  ///
  /// A fresh 256-bit nonce and a fresh ephemeral ECDH key are drawn per
  /// attempt from the injected CSPRNG, so every reconnect is cryptographically
  /// independent of the last. The statement signature binds the device's
  /// long-term key to those contributions; it is not a freshness proof, which
  /// is why the host commits nothing until message 3.
  public func beginAuthentication(
    selection proposed: SecureProtocolSelection? = nil
  ) throws -> SessionDeviceAttempt {
    let selection = try proposed ?? SessionPolicy.requiredSelection()
    guard (try? SecureProtocolNegotiation.accept(selection)) != nil else {
      throw SessionClosedReason.selectionRejected
    }
    let nonce = try entropy(SessionPolicy.nonceByteCount)
    let ephemeral = try ephemeralPrivateKey()
    let statement = try SessionAuthenticationStatement(
      hostID: hostID,
      deviceID: identity.deviceID,
      selection: selection,
      deviceEphemeralPublicKey: ephemeral.publicKey.x963Representation,
      deviceNonce: nonce
    )
    let request = try SecureSessionAuthRequest(
      deviceID: identity.deviceID,
      selection: selection,
      deviceEphemeralPublicKey: ephemeral.publicKey.x963Representation,
      deviceNonce: nonce,
      transcriptSignature: try sign(statement.canonicalEncoding())
    )
    return SessionDeviceAttempt(
      request: request,
      statement: statement,
      ephemeral: ephemeral,
      identity: identity,
      hostPublicKeyX963: hostPublicKeyX963,
      hostTLSSPKIFingerprint: hostTLSSPKIFingerprint
    )
  }

  private func sign(_ canonicalBytes: Data) throws -> Data {
    guard let signature = try? identity.signer.signSessionStatement(canonicalBytes),
      signature.count == SecureTranscriptSignature.byteCount
    else {
      throw SessionClosedReason.deviceSignatureUnavailable
    }
    return signature
  }

  private func entropy(_ count: Int) throws -> Data {
    guard let bytes = try? random.randomBytes(count: count), bytes.count == count else {
      throw SessionClosedReason.entropyUnavailable
    }
    return bytes
  }

  private func ephemeralPrivateKey() throws -> P256.KeyAgreement.PrivateKey {
    let scalar = try entropy(SessionPolicy.ephemeralScalarByteCount)
    guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: scalar) else {
      throw SessionClosedReason.entropyUnavailable
    }
    return key
  }
}

/// One in-flight device authentication attempt, holding the attempt-local
/// ephemeral key that binds the session.
public struct SessionDeviceAttempt: Sendable {
  /// Message 1, to send to the host.
  public let request: SecureSessionAuthRequest
  /// The canonical statement the device signed in message 1.
  public let statement: SessionAuthenticationStatement
  private let ephemeral: P256.KeyAgreement.PrivateKey
  private let identity: SessionDeviceIdentity
  private let hostPublicKeyX963: Data
  private let hostTLSSPKIFingerprint: Data

  init(
    request: SecureSessionAuthRequest,
    statement: SessionAuthenticationStatement,
    ephemeral: P256.KeyAgreement.PrivateKey,
    identity: SessionDeviceIdentity,
    hostPublicKeyX963: Data,
    hostTLSSPKIFingerprint: Data
  ) {
    self.request = request
    self.statement = statement
    self.ephemeral = ephemeral
    self.identity = identity
    self.hostPublicKeyX963 = hostPublicKeyX963
    self.hostTLSSPKIFingerprint = hostTLSSPKIFingerprint
  }

  /// Verifies message 2, signs the same transcript as message 3, and derives
  /// the session's directional keys.
  ///
  /// The transcript is rebuilt from the device's own contributions, the
  /// reply's, and the device's pinned TLS SPKI fingerprint, so the host
  /// signature is checked against exactly what the device believes; any
  /// altered or substituted field fails closed. Frame counters start at 0 in
  /// both directions and the frame header binds this session's fresh session
  /// ID.
  public func completeAuthentication(
    with response: SecureSessionAuthResponse
  ) throws -> DeviceSessionCompletion {
    guard response.selection == request.selection else {
      throw SessionClosedReason.selectionRejected
    }
    guard
      let transcript = try? SessionTranscript(
        sessionID: response.sessionID,
        deviceID: request.deviceID,
        selection: response.selection,
        deviceEphemeralPublicKey: request.deviceEphemeralPublicKey,
        deviceNonce: request.deviceNonce,
        hostEphemeralPublicKey: response.hostEphemeralPublicKey,
        hostNonce: response.hostNonce,
        hostTLSSPKIFingerprint: hostTLSSPKIFingerprint
      )
    else {
      throw SessionClosedReason.malformedResponse
    }
    guard
      let hostPublicKey = try? SecureP256KeyEncoding.signingPublicKey(fromX963: hostPublicKeyX963),
      SecureTranscriptSignature.isValid(
        response.transcriptSignature,
        for: transcript.canonicalEncoding(),
        publicKey: hostPublicKey
      )
    else {
      throw SessionClosedReason.hostSignatureInvalid
    }
    guard let signature = try? identity.signer.signSessionStatement(transcript.canonicalEncoding()),
      signature.count == SecureTranscriptSignature.byteCount
    else {
      throw SessionClosedReason.deviceSignatureUnavailable
    }
    guard
      let sharedSecret = try? SecureKeyAgreement.sharedSecret(
        privateKey: ephemeral, peerPublicKeyX963: response.hostEphemeralPublicKey),
      let keys = try? SecureSessionKeySchedule.frameKeys(
        sharedSecret: sharedSecret,
        sessionTranscriptHash: transcript.canonicalHash(),
        selection: transcript.selection
      ),
      let outbound = try? SecureFrameSealer(
        key: keys.clientToServer,
        connectionID: response.sessionID,
        direction: .clientToServer
      ),
      let inbound = try? SecureFrameOpener(
        key: keys.serverToClient,
        connectionID: response.sessionID,
        direction: .serverToClient
      )
    else {
      throw SessionClosedReason.keyAgreementFailed
    }
    return DeviceSessionCompletion(
      confirmation: try SecureSessionAuthConfirmation(
        sessionID: response.sessionID,
        deviceID: request.deviceID,
        transcriptSignature: signature
      ),
      session: EstablishedDeviceSession(
        sessionID: response.sessionID,
        deviceID: request.deviceID,
        transcript: transcript,
        outbound: outbound,
        inbound: inbound
      )
    )
  }
}

extension SessionDeviceAttempt: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the attempt holds the attempt-local ephemeral private key.
  public var description: String { "SessionDeviceAttempt(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}
