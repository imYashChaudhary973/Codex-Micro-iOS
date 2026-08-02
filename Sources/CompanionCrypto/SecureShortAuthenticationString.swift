import CompanionProtocol
import CryptoKit
import Foundation

/// Transcript-bound short authentication string: exactly 66 uniformly
/// derived bits presented as six 11-bit indices into a fixed, versioned
/// 2048-entry list.
///
/// Derivation is HKDF-SHA256 with the SAS-specific canonical label over the
/// SHA-256 hash of the canonical pairing transcript. Nine output bytes
/// (72 bits) are produced and exactly the first 66 bits are consumed as six
/// big-endian 11-bit slices — each index is uniform over `0..<2048` with no
/// modulo bias, and the trailing 6 bits are discarded.
///
/// Step 2.3 exposes the indices and their canonical zero-padded decimal
/// group rendering (for example `0417-1023-...`). Mapping indices to the
/// fixed versioned word list is a Step 2.13 UI concern; the derived indices
/// are already final and version-bound through the SAS domain separator.
public struct SecureShortAuthenticationString: Equatable, Sendable {
  /// Number of derived indices (display groups).
  public static let indexCount = 6
  /// Bits consumed per index.
  public static let bitsPerIndex = 11
  /// Total derived entropy in bits, consumed exactly.
  public static let derivedBitCount = 66
  /// Exclusive upper bound of every index (the word-list size).
  public static let indexUpperBound: UInt16 = 2048
  static let derivedByteCount = 9

  /// Exactly six indices, each in `0..<2048`.
  public let indices: [UInt16]

  init(indices: [UInt16]) {
    precondition(indices.count == Self.indexCount, "SAS requires exactly six indices")
    precondition(
      indices.allSatisfy { $0 < Self.indexUpperBound },
      "SAS index outside the 11-bit range"
    )
    self.indices = indices
  }

  /// Derives the SAS for a complete pairing transcript. Both endpoints
  /// derive independently and must display identical groups.
  public static func derive(from transcript: PairingTranscript) -> SecureShortAuthenticationString {
    deriveCore(fromValidatedHash: transcript.canonicalHash())
  }

  /// Derives the SAS from an externally computed 32-byte pairing-transcript
  /// hash. Any other hash length fails closed.
  public static func derive(
    fromTranscriptHash hash: Data
  ) throws -> SecureShortAuthenticationString {
    try requireExactCryptoByteCount(hash, 32, field: "pairingTranscriptHash")
    return deriveCore(fromValidatedHash: hash)
  }

  /// The canonical HKDF info label: version byte plus the SAS domain.
  static var derivationLabel: Data {
    CanonicalStatementEncoder(domain: .shortAuthenticationString).encodedBytes
  }

  private static func deriveCore(fromValidatedHash hash: Data) -> SecureShortAuthenticationString {
    let output = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: hash),
      salt: Data(),
      info: derivationLabel,
      outputByteCount: derivedByteCount
    )
    return SecureShortAuthenticationString(
      indices: unpackIndices(output.withUnsafeBytes { Data($0) }))
  }

  /// Splits the first 66 bits of nine bytes into six big-endian 11-bit
  /// indices, discarding the trailing 6 bits.
  static func unpackIndices(_ bytes: Data) -> [UInt16] {
    precondition(bytes.count == derivedByteCount, "SAS derivation requires exactly nine bytes")
    var indices: [UInt16] = []
    var accumulator: UInt32 = 0
    var accumulatedBits = 0
    for byte in bytes {
      accumulator = (accumulator << 8) | UInt32(byte)
      accumulatedBits += 8
      while accumulatedBits >= bitsPerIndex, indices.count < indexCount {
        accumulatedBits -= bitsPerIndex
        indices.append(UInt16((accumulator >> UInt32(accumulatedBits)) & 0x7FF))
        accumulator &= (1 << UInt32(accumulatedBits)) - 1
      }
    }
    return indices
  }

  /// Canonical zero-padded four-digit decimal rendering of each index.
  public var displayGroups: [String] {
    indices.map { String(format: "%04d", Int($0)) }
  }

  /// The six groups joined with hyphens, e.g. `0417-1023-0004-2047-0000-0512`.
  public var displayString: String {
    displayGroups.joined(separator: "-")
  }
}
