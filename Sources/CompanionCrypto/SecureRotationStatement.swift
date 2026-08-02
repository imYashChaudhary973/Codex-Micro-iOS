import CompanionProtocol
import CryptoKit
import Foundation

/// Canonical TLS-key rotation statement (ADR §7/§11). Binds the expected
/// current SPKI fingerprint, the presented next SPKI fingerprint, a strictly
/// increasing rotation generation, and an explicit validity interval in epoch
/// seconds. Generation `0` is the pre-rotation baseline and is never a valid
/// statement generation.
public struct SecureRotationStatement: Equatable, Sendable {
  public let rotationGeneration: UInt64
  public let currentSPKIFingerprint: Data
  public let nextSPKIFingerprint: Data
  public let validityStartEpochSeconds: UInt64
  public let validityEndEpochSeconds: UInt64

  public init(
    rotationGeneration: UInt64,
    currentSPKIFingerprint: Data,
    nextSPKIFingerprint: Data,
    validityStartEpochSeconds: UInt64,
    validityEndEpochSeconds: UInt64
  ) throws {
    guard rotationGeneration >= 1 else {
      throw SecureWireValidationError.invalidField(name: "rotationGeneration")
    }
    try requireExactCryptoByteCount(
      currentSPKIFingerprint, SPKIFingerprint.byteCount, field: "currentSPKIFingerprint")
    try requireExactCryptoByteCount(
      nextSPKIFingerprint, SPKIFingerprint.byteCount, field: "nextSPKIFingerprint")
    guard currentSPKIFingerprint != nextSPKIFingerprint else {
      throw SecureWireValidationError.invalidField(name: "nextSPKIFingerprint")
    }
    guard validityStartEpochSeconds < validityEndEpochSeconds else {
      throw SecureWireValidationError.invalidField(name: "validityEndEpochSeconds")
    }
    self.rotationGeneration = rotationGeneration
    self.currentSPKIFingerprint = currentSPKIFingerprint
    self.nextSPKIFingerprint = nextSPKIFingerprint
    self.validityStartEpochSeconds = validityStartEpochSeconds
    self.validityEndEpochSeconds = validityEndEpochSeconds
  }

  /// Strictly decodes a canonical rotation-statement encoding. Wrong version,
  /// wrong domain, wrong field lengths, truncation, trailing bytes, or any
  /// semantic violation fails closed.
  public init(canonicalEncoding: Data) throws {
    var reader = try CanonicalStatementReader(canonicalEncoding, domain: .rotationStatement)
    let generation = try reader.readUInt64()
    let current = try reader.readVariableBytes(exactCount: SPKIFingerprint.byteCount)
    let next = try reader.readVariableBytes(exactCount: SPKIFingerprint.byteCount)
    let start = try reader.readUInt64()
    let end = try reader.readUInt64()
    try reader.requireEnd()
    try self.init(
      rotationGeneration: generation,
      currentSPKIFingerprint: current,
      nextSPKIFingerprint: next,
      validityStartEpochSeconds: start,
      validityEndEpochSeconds: end
    )
  }

  /// The canonical, injective byte encoding of this statement.
  public func canonicalEncoding() -> Data {
    var encoder = CanonicalStatementEncoder(domain: .rotationStatement)
    encoder.appendUInt64(rotationGeneration)
    encoder.appendVariableBytes(currentSPKIFingerprint)
    encoder.appendVariableBytes(nextSPKIFingerprint)
    encoder.appendUInt64(validityStartEpochSeconds)
    encoder.appendUInt64(validityEndEpochSeconds)
    return encoder.encodedBytes
  }
}

/// Closed rotation-verification failure vocabulary; carries no content.
public enum SecureRotationError: Error, Equatable, Sendable {
  case invalidSignature
  case currentPinMismatch
  case nonMonotonicGeneration
  case notYetValid
  case expired
}

/// Pure host-signed rotation-statement signing and verification (ADR §7).
/// Storage of the pinned SPKI and the accepted generation stays elsewhere;
/// callers pass current values in and persist the new generation only after
/// verification succeeds.
public enum SecureRotationVerifier {
  /// Signs the canonical statement bytes with the long-term host identity,
  /// producing exactly 64 raw `r||s` bytes.
  public static func sign(
    _ statement: SecureRotationStatement,
    using hostPrivateKey: P256.Signing.PrivateKey
  ) throws -> Data {
    try SecureTranscriptSignature.sign(statement.canonicalEncoding(), using: hostPrivateKey)
  }

  /// Verifies a rotation statement fail-closed, in fixed order: host
  /// signature over the canonical bytes, current-SPKI pin binding, strict
  /// generation monotonicity (`statement > lastAccepted`), then the validity
  /// interval evaluated at the injected time (inclusive bounds).
  public static func verify(
    statement: SecureRotationStatement,
    signature: Data,
    hostPublicKey: P256.Signing.PublicKey,
    pinnedCurrentSPKIFingerprint: Data,
    lastAcceptedGeneration: UInt64,
    atEpochSeconds now: UInt64
  ) throws {
    guard
      SecureTranscriptSignature.isValid(
        signature, for: statement.canonicalEncoding(), publicKey: hostPublicKey)
    else {
      throw SecureRotationError.invalidSignature
    }
    guard statement.currentSPKIFingerprint == pinnedCurrentSPKIFingerprint else {
      throw SecureRotationError.currentPinMismatch
    }
    guard statement.rotationGeneration > lastAcceptedGeneration else {
      throw SecureRotationError.nonMonotonicGeneration
    }
    guard now >= statement.validityStartEpochSeconds else {
      throw SecureRotationError.notYetValid
    }
    guard now <= statement.validityEndEpochSeconds else {
      throw SecureRotationError.expired
    }
  }
}
