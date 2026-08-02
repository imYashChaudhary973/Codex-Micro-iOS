import CompanionProtocol
import CryptoKit
import Foundation

/// SHA-256 fingerprints over P-256 SubjectPublicKeyInfo DER (ADR §7).
///
/// Clients pin this fingerprint — never certificate bytes — so same-key
/// certificate renewal is transparent while any key change is visible.
public enum SPKIFingerprint {
  /// Exact byte count of a SPKI fingerprint (SHA-256).
  public static let byteCount = 32

  /// Exact byte count of a P-256 uncompressed SubjectPublicKeyInfo DER.
  public static let derByteCount = 91

  /// Fixed DER prefix of a SubjectPublicKeyInfo carrying an uncompressed
  /// P-256 point: SEQUENCE(SEQUENCE(OID id-ecPublicKey, OID prime256v1),
  /// BIT STRING(0x00 unused-bits byte, 65-byte X9.63 point)).
  private static let subjectPublicKeyInfoPrefix = Data([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00,
  ])

  /// Builds the SPKI DER for a strictly validated X9.63 public key.
  public static func subjectPublicKeyInfoDER(x963PublicKey: Data) throws -> Data {
    _ = try SecureP256KeyEncoding.signingPublicKey(fromX963: x963PublicKey)
    return subjectPublicKeyInfoPrefix + x963PublicKey
  }

  /// SHA-256 over the SPKI DER of a strictly validated X9.63 public key.
  public static func fingerprint(x963PublicKey: Data) throws -> Data {
    Data(SHA256.hash(data: try subjectPublicKeyInfoDER(x963PublicKey: x963PublicKey)))
  }

  /// SHA-256 over the SPKI DER of an already-validated CryptoKit key.
  public static func fingerprint(of key: P256.Signing.PublicKey) -> Data {
    Data(SHA256.hash(data: subjectPublicKeyInfoPrefix + key.x963Representation))
  }
}
