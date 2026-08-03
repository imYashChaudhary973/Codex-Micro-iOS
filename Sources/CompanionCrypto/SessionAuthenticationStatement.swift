import CompanionProtocol
import CryptoKit
import Foundation

/// Canonical session-authentication statement (ADR §11): the exact bytes a
/// paired device signs with its long-term identity when it asks to open a
/// session, binding the host it is talking to, its own asserted device ID,
/// the exact negotiated protocol tuple, and its two fresh contributions.
///
/// It exists because the ``SessionTranscript`` cannot be signed by the device
/// first: the transcript binds the Mac's current grant revision,
/// authorized-view epoch, and host generation, and disclosing those to an
/// unauthenticated client would leak grant metadata (plan §7 gate 2). The
/// device therefore signs this statement, the host verifies it against the
/// authority's stored device key, and only then does the host sign the full
/// transcript back. Both endpoints still derive their frame keys from the
/// complete transcript hash, so any disagreement about the transcript yields
/// unusable keys.
public struct SessionAuthenticationStatement: Equatable, Sendable {
  public let hostID: UUID
  public let deviceID: UUID
  public let selection: SecureProtocolSelection
  public let deviceEphemeralPublicKey: Data
  public let deviceNonce: Data

  public init(
    hostID: UUID,
    deviceID: UUID,
    selection: SecureProtocolSelection,
    deviceEphemeralPublicKey: Data,
    deviceNonce: Data
  ) throws {
    try requireExactCryptoByteCount(
      deviceEphemeralPublicKey,
      SecureTransportLimits.publicKeyByteCount,
      field: "deviceEphemeralPublicKey"
    )
    try requireExactCryptoByteCount(
      deviceNonce, SecureTransportLimits.nonceByteCount, field: "deviceNonce")
    self.hostID = hostID
    self.deviceID = deviceID
    self.selection = selection
    self.deviceEphemeralPublicKey = deviceEphemeralPublicKey
    self.deviceNonce = deviceNonce
  }

  /// Builds the statement a received authentication request asserts.
  public init(hostID: UUID, request: SecureSessionAuthRequest) throws {
    try self.init(
      hostID: hostID,
      deviceID: request.deviceID,
      selection: request.selection,
      deviceEphemeralPublicKey: request.deviceEphemeralPublicKey,
      deviceNonce: request.deviceNonce
    )
  }

  /// The canonical, injective byte encoding of this statement.
  public func canonicalEncoding() -> Data {
    var encoder = CanonicalStatementEncoder(domain: .sessionAuthenticationStatement)
    encoder.appendUUID(hostID)
    encoder.appendUUID(deviceID)
    encoder.appendSelection(selection)
    encoder.appendVariableBytes(deviceEphemeralPublicKey)
    encoder.appendVariableBytes(deviceNonce)
    return encoder.encodedBytes
  }

  /// SHA-256 over the canonical encoding.
  ///
  /// The host records this digest with the session it establishes, so a
  /// byte-identical replay of a captured request cannot silently supersede
  /// the live session it was captured from.
  public func canonicalHash() -> Data {
    Data(SHA256.hash(data: canonicalEncoding()))
  }
}
