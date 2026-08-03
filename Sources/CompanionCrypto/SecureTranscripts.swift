import CompanionProtocol
import CryptoKit
import Foundation

/// Canonical pairing transcript (ADR §11) binding every field either endpoint
/// contributed during pairing, in fixed order: the pairing session, mode,
/// normalized endpoint origin, exact negotiated protocol tuple, single-use
/// bootstrap secret, both 256-bit nonces, both long-term X9.63 public keys,
/// the opaque host ID, and the current TLS SPKI fingerprint.
///
/// Both endpoints construct the transcript independently from the exchanged
/// message fields; the Step 2.5 pairing state machine decides which endpoint
/// signs which transcript-bound statement. Field byte counts are validated at
/// initialization, so encoding itself cannot fail.
public struct PairingTranscript: Equatable, Sendable {
  public let pairingSessionID: UUID
  public let mode: SecurePairingMode
  public let endpointOrigin: String
  public let selection: SecureProtocolSelection
  public let bootstrapSecret: Data
  public let deviceNonce: Data
  public let devicePublicKey: Data
  public let hostID: UUID
  public let hostNonce: Data
  public let hostPublicKey: Data
  public let hostTLSSPKIFingerprint: Data

  public init(
    pairingSessionID: UUID,
    mode: SecurePairingMode,
    endpointOrigin: String,
    selection: SecureProtocolSelection,
    bootstrapSecret: Data,
    deviceNonce: Data,
    devicePublicKey: Data,
    hostID: UUID,
    hostNonce: Data,
    hostPublicKey: Data,
    hostTLSSPKIFingerprint: Data
  ) throws {
    try requireBoundedCryptoText(
      endpointOrigin,
      maxUTF8: SecureTransportLimits.maxEndpointOriginBytes,
      field: "endpointOrigin"
    )
    try requireExactCryptoByteCount(
      bootstrapSecret, SecureTransportLimits.bootstrapSecretByteCount, field: "bootstrapSecret")
    try requireExactCryptoByteCount(
      deviceNonce, SecureTransportLimits.nonceByteCount, field: "deviceNonce")
    try requireExactCryptoByteCount(
      devicePublicKey, SecureTransportLimits.publicKeyByteCount, field: "devicePublicKey")
    try requireExactCryptoByteCount(
      hostNonce, SecureTransportLimits.nonceByteCount, field: "hostNonce")
    try requireExactCryptoByteCount(
      hostPublicKey, SecureTransportLimits.publicKeyByteCount, field: "hostPublicKey")
    try requireExactCryptoByteCount(
      hostTLSSPKIFingerprint, SPKIFingerprint.byteCount, field: "hostTLSSPKIFingerprint")
    self.pairingSessionID = pairingSessionID
    self.mode = mode
    self.endpointOrigin = endpointOrigin
    self.selection = selection
    self.bootstrapSecret = bootstrapSecret
    self.deviceNonce = deviceNonce
    self.devicePublicKey = devicePublicKey
    self.hostID = hostID
    self.hostNonce = hostNonce
    self.hostPublicKey = hostPublicKey
    self.hostTLSSPKIFingerprint = hostTLSSPKIFingerprint
  }

  /// The canonical, injective byte encoding of this transcript.
  public func canonicalEncoding() -> Data {
    var encoder = CanonicalStatementEncoder(domain: .pairingTranscript)
    encoder.appendUUID(pairingSessionID)
    encoder.appendText(mode.rawValue)
    encoder.appendText(endpointOrigin)
    encoder.appendSelection(selection)
    encoder.appendVariableBytes(bootstrapSecret)
    encoder.appendVariableBytes(deviceNonce)
    encoder.appendVariableBytes(devicePublicKey)
    encoder.appendUUID(hostID)
    encoder.appendVariableBytes(hostNonce)
    encoder.appendVariableBytes(hostPublicKey)
    encoder.appendVariableBytes(hostTLSSPKIFingerprint)
    return encoder.encodedBytes
  }

  /// SHA-256 over the canonical encoding; the input to SAS derivation.
  public func canonicalHash() -> Data {
    Data(SHA256.hash(data: canonicalEncoding()))
  }
}

extension PairingTranscript: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the transcript binds the single-use bootstrap secret, so no
  /// description, interpolation, or reflection path may render its fields.
  public var description: String { "PairingTranscript(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// Canonical session-authentication transcript (ADR §11) binding the session
/// ID, authenticated device, exact negotiated protocol tuple, both ephemeral
/// ECDH contributions and nonces, and the pinned TLS SPKI fingerprint of the
/// channel the session runs over.
///
/// **Both endpoints sign exactly this**, in the order host then device, and
/// its hash salts the directional frame-key schedule. It carries no Mac
/// authority counter on purpose: the device must sign the transcript to prove
/// handshake freshness, and it can only do that if the transcript is
/// exchangeable before the device is authenticated — so nothing in it may be
/// authorization state (plan §7 gate 2). The Mac's grant revision,
/// authorized-view epoch, and host generation are enforced host-side against
/// the registered session and delivered only in sealed post-authentication
/// traffic.
///
/// Binding `hostTLSSPKIFingerprint` ties the session to the same pinned
/// channel identity pairing already binds, so a session transcript is not
/// transferable to a different TLS identity.
public struct SessionTranscript: Equatable, Sendable {
  public let sessionID: UUID
  public let deviceID: UUID
  public let selection: SecureProtocolSelection
  public let deviceEphemeralPublicKey: Data
  public let deviceNonce: Data
  public let hostEphemeralPublicKey: Data
  public let hostNonce: Data
  public let hostTLSSPKIFingerprint: Data

  public init(
    sessionID: UUID,
    deviceID: UUID,
    selection: SecureProtocolSelection,
    deviceEphemeralPublicKey: Data,
    deviceNonce: Data,
    hostEphemeralPublicKey: Data,
    hostNonce: Data,
    hostTLSSPKIFingerprint: Data
  ) throws {
    try requireExactCryptoByteCount(
      deviceEphemeralPublicKey,
      SecureTransportLimits.publicKeyByteCount,
      field: "deviceEphemeralPublicKey"
    )
    try requireExactCryptoByteCount(
      deviceNonce, SecureTransportLimits.nonceByteCount, field: "deviceNonce")
    try requireExactCryptoByteCount(
      hostEphemeralPublicKey,
      SecureTransportLimits.publicKeyByteCount,
      field: "hostEphemeralPublicKey"
    )
    try requireExactCryptoByteCount(
      hostNonce, SecureTransportLimits.nonceByteCount, field: "hostNonce")
    try requireExactCryptoByteCount(
      hostTLSSPKIFingerprint, SPKIFingerprint.byteCount, field: "hostTLSSPKIFingerprint")
    self.sessionID = sessionID
    self.deviceID = deviceID
    self.selection = selection
    self.deviceEphemeralPublicKey = deviceEphemeralPublicKey
    self.deviceNonce = deviceNonce
    self.hostEphemeralPublicKey = hostEphemeralPublicKey
    self.hostNonce = hostNonce
    self.hostTLSSPKIFingerprint = hostTLSSPKIFingerprint
  }

  /// The canonical, injective byte encoding of this transcript.
  public func canonicalEncoding() -> Data {
    var encoder = CanonicalStatementEncoder(domain: .sessionTranscript)
    encoder.appendUUID(sessionID)
    encoder.appendUUID(deviceID)
    encoder.appendSelection(selection)
    encoder.appendVariableBytes(deviceEphemeralPublicKey)
    encoder.appendVariableBytes(deviceNonce)
    encoder.appendVariableBytes(hostEphemeralPublicKey)
    encoder.appendVariableBytes(hostNonce)
    encoder.appendVariableBytes(hostTLSSPKIFingerprint)
    return encoder.encodedBytes
  }

  /// SHA-256 over the canonical encoding; the salt of the frame-key schedule.
  public func canonicalHash() -> Data {
    Data(SHA256.hash(data: canonicalEncoding()))
  }
}
