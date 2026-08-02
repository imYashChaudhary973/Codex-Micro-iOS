import CompanionProtocol
import CryptoKit
import Foundation

/// Strict conversions between 65-byte X9.63 uncompressed P-256 public keys
/// and CryptoKit key types. Wrong lengths, compressed points, and off-curve
/// points fail closed.
public enum SecureP256KeyEncoding {
  /// Exact byte count of an X9.63 uncompressed P-256 public key.
  public static let x963ByteCount = SecureTransportLimits.publicKeyByteCount
  private static let uncompressedPointTag: UInt8 = 0x04

  public static func signingPublicKey(fromX963 encoded: Data) throws -> P256.Signing.PublicKey {
    try validateShape(encoded)
    guard let key = try? P256.Signing.PublicKey(x963Representation: encoded) else {
      throw SecureWireValidationError.invalidField(name: "publicKey")
    }
    return key
  }

  public static func keyAgreementPublicKey(
    fromX963 encoded: Data
  ) throws -> P256.KeyAgreement.PublicKey {
    try validateShape(encoded)
    guard let key = try? P256.KeyAgreement.PublicKey(x963Representation: encoded) else {
      throw SecureWireValidationError.invalidField(name: "publicKey")
    }
    return key
  }

  public static func x963Representation(of key: P256.Signing.PublicKey) -> Data {
    key.x963Representation
  }

  public static func x963Representation(of key: P256.KeyAgreement.PublicKey) -> Data {
    key.x963Representation
  }

  private static func validateShape(_ encoded: Data) throws {
    guard encoded.count == x963ByteCount, encoded.first == uncompressedPointTag else {
      throw SecureWireValidationError.invalidField(name: "publicKey")
    }
  }
}

/// P-256 signatures over canonical statement bytes, produced and consumed as
/// exactly 64 raw `r||s` bytes (ADR §11). DER-wrapped or wrong-length
/// signatures never verify.
public enum SecureTranscriptSignature {
  /// Exact byte count of a raw `r||s` P-256 signature.
  public static let byteCount = SecureTransportLimits.signatureByteCount

  /// Signs canonical statement bytes, returning exactly 64 raw `r||s` bytes.
  public static func sign(
    _ statement: Data,
    using privateKey: P256.Signing.PrivateKey
  ) throws -> Data {
    try privateKey.signature(for: statement).rawRepresentation
  }

  /// Verifies exactly 64 raw `r||s` signature bytes over canonical statement
  /// bytes. Any other length — including DER — fails closed.
  public static func isValid(
    _ signature: Data,
    for statement: Data,
    publicKey: P256.Signing.PublicKey
  ) -> Bool {
    guard signature.count == byteCount,
      let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
    else {
      return false
    }
    return publicKey.isValidSignature(parsed, for: statement)
  }
}

/// Ephemeral P-256 ECDH key agreement for session handshakes. Every session
/// uses a fresh ephemeral private key; nothing here persists key material.
public enum SecureKeyAgreement {
  /// Mints a fresh ephemeral ECDH private key for one handshake attempt.
  public static func makeEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey {
    P256.KeyAgreement.PrivateKey()
  }

  /// Performs ECDH against a strictly validated X9.63 peer public key.
  public static func sharedSecret(
    privateKey: P256.KeyAgreement.PrivateKey,
    peerPublicKeyX963: Data
  ) throws -> SharedSecret {
    let peer = try SecureP256KeyEncoding.keyAgreementPublicKey(fromX963: peerPublicKeyX963)
    return try privateKey.sharedSecretFromKeyAgreement(with: peer)
  }
}
