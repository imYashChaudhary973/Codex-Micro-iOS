import CompanionProtocol
import CryptoKit
import Foundation

/// The two independent 256-bit ChaCha20-Poly1305 directional frame keys of
/// one authenticated session. Directions never share a key.
public struct SecureDirectionalFrameKeys: Sendable {
  public let clientToServer: SymmetricKey
  public let serverToClient: SymmetricKey

  public init(clientToServer: SymmetricKey, serverToClient: SymmetricKey) {
    self.clientToServer = clientToServer
    self.serverToClient = serverToClient
  }
}

/// HKDF-SHA256 key schedule for directional application-frame keys.
///
/// Fixed policy (ADR §11): the input key material is the ephemeral ECDH
/// shared secret; the salt is the SHA-256 hash of the canonical session
/// transcript; and each direction's info label is the canonical encoding of
/// that direction's domain separator followed by the exact negotiated
/// protocol tuple. Both endpoints therefore derive identical keys only when
/// they agree on the complete transcript and negotiated tuple.
public enum SecureSessionKeySchedule {
  /// Exact byte count of each derived directional frame key (256 bits).
  public static let frameKeyByteCount = 32
  private static let transcriptHashByteCount = 32

  /// Derives both directional frame keys from an ECDH shared secret.
  public static func frameKeys(
    sharedSecret: SharedSecret,
    sessionTranscriptHash: Data,
    selection: SecureProtocolSelection
  ) throws -> SecureDirectionalFrameKeys {
    try frameKeys(
      inputKeyMaterial: SymmetricKey(data: sharedSecret),
      sessionTranscriptHash: sessionTranscriptHash,
      selection: selection
    )
  }

  /// Derives both directional frame keys from raw input key material. This
  /// overload exists so golden vectors can pin the schedule byte-exactly.
  public static func frameKeys(
    inputKeyMaterial: SymmetricKey,
    sessionTranscriptHash: Data,
    selection: SecureProtocolSelection
  ) throws -> SecureDirectionalFrameKeys {
    try requireExactCryptoByteCount(
      sessionTranscriptHash, transcriptHashByteCount, field: "sessionTranscriptHash")
    return SecureDirectionalFrameKeys(
      clientToServer: deriveKey(
        inputKeyMaterial: inputKeyMaterial,
        salt: sessionTranscriptHash,
        label: directionLabel(.frameKeyClientToServer, selection: selection)
      ),
      serverToClient: deriveKey(
        inputKeyMaterial: inputKeyMaterial,
        salt: sessionTranscriptHash,
        label: directionLabel(.frameKeyServerToClient, selection: selection)
      )
    )
  }

  /// The canonical info label for one direction: version byte, direction
  /// domain separator, then the exact negotiated `(major, minor, features)`.
  static func directionLabel(
    _ domain: CanonicalStatementDomain,
    selection: SecureProtocolSelection
  ) -> Data {
    var encoder = CanonicalStatementEncoder(domain: domain)
    encoder.appendSelection(selection)
    return encoder.encodedBytes
  }

  private static func deriveKey(
    inputKeyMaterial: SymmetricKey,
    salt: Data,
    label: Data
  ) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(
      inputKeyMaterial: inputKeyMaterial,
      salt: salt,
      info: label,
      outputByteCount: frameKeyByteCount
    )
  }
}
