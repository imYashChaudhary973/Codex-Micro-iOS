import CompanionProtocol
import CryptoKit
import Foundation

/// The complete content of a pairing QR code (ADR §12 allowlist).
///
/// The allowlist is exact and closed. The payload carries exactly:
/// the canonical statement version, the exact protocol/feature selection, the
/// opaque host ID, the normalized direct-LAN endpoint origin, the
/// host-identity SPKI fingerprint, the current TLS SPKI fingerprint, the
/// pairing session ID, the 256-bit one-time bootstrap secret, and the
/// expiry instant in epoch seconds.
///
/// It carries **no `hostName`**, display name, device, user, or project data.
/// The device learns a display name only from the authenticated exchange that
/// follows, never from the QR.
///
/// The encoding is the ADR §11 canonical form under its own domain separator,
/// so the QR bytes are unambiguous: strict decoding rejects a wrong version,
/// a foreign domain, wrong field lengths, unknown or misordered features,
/// truncation, trailing bytes, and any origin that is not already normalized.
public struct PairingQRPayload: Equatable, Sendable {
  /// The canonical statement version byte that leads the encoding. It is the
  /// payload's `version` field; a future layout mints a new domain and
  /// version pair.
  public static var version: UInt8 { CanonicalStatementVersion.current }

  /// The exact `(major, minor, feature set)` the host will accept.
  public let selection: SecureProtocolSelection
  /// Opaque host identifier. Possession never authenticates.
  public let hostID: UUID
  /// The normalized direct-LAN endpoint origin.
  public let endpointOrigin: PairingEndpointOrigin
  /// SHA-256 SPKI fingerprint of the long-term host identity key.
  public let hostIdentityFingerprint: Data
  /// SHA-256 SPKI fingerprint of the currently presented TLS key.
  public let tlsSPKIFingerprint: Data
  /// Non-secret pairing-session lookup identifier.
  public let pairingSessionID: UUID
  /// The single-use 256-bit CSPRNG bootstrap secret.
  public let bootstrapSecret: Data
  /// Expiry instant in epoch seconds; the session is expired at this value.
  public let expiresAtEpochSeconds: UInt64

  public init(
    selection: SecureProtocolSelection,
    hostID: UUID,
    endpointOrigin: PairingEndpointOrigin,
    hostIdentityFingerprint: Data,
    tlsSPKIFingerprint: Data,
    pairingSessionID: UUID,
    bootstrapSecret: Data,
    expiresAtEpochSeconds: UInt64
  ) throws {
    try requireExactCryptoByteCount(
      hostIdentityFingerprint, SPKIFingerprint.byteCount, field: "hostIdentityFingerprint")
    try requireExactCryptoByteCount(
      tlsSPKIFingerprint, SPKIFingerprint.byteCount, field: "tlsSPKIFingerprint")
    try requireExactCryptoByteCount(
      bootstrapSecret, SecureTransportLimits.bootstrapSecretByteCount, field: "bootstrapSecret")
    self.selection = selection
    self.hostID = hostID
    self.endpointOrigin = endpointOrigin
    self.hostIdentityFingerprint = hostIdentityFingerprint
    self.tlsSPKIFingerprint = tlsSPKIFingerprint
    self.pairingSessionID = pairingSessionID
    self.bootstrapSecret = bootstrapSecret
    self.expiresAtEpochSeconds = expiresAtEpochSeconds
  }

  /// Strictly decodes canonical QR bytes. Every violation fails closed.
  public init(canonicalEncoding: Data) throws {
    var reader = try CanonicalStatementReader(canonicalEncoding, domain: .pairingQRPayload)
    let selection = try reader.readSelection()
    let hostID = try reader.readUUID()
    let originText = try reader.readText()
    let hostIdentityFingerprint = try reader.readVariableBytes(
      exactCount: SPKIFingerprint.byteCount)
    let tlsSPKIFingerprint = try reader.readVariableBytes(exactCount: SPKIFingerprint.byteCount)
    let pairingSessionID = try reader.readUUID()
    let bootstrapSecret = try reader.readVariableBytes(
      exactCount: SecureTransportLimits.bootstrapSecretByteCount)
    let expiresAt = try reader.readUInt64()
    try reader.requireEnd()

    guard let origin = try? PairingEndpointOrigin(originText), origin.normalized == originText
    else {
      throw SecureWireValidationError.invalidField(name: "endpointOrigin")
    }
    try self.init(
      selection: selection,
      hostID: hostID,
      endpointOrigin: origin,
      hostIdentityFingerprint: hostIdentityFingerprint,
      tlsSPKIFingerprint: tlsSPKIFingerprint,
      pairingSessionID: pairingSessionID,
      bootstrapSecret: bootstrapSecret,
      expiresAtEpochSeconds: expiresAt
    )
  }

  /// The exact ADR §12 allowlist, in canonical encoding order.
  ///
  /// The byte-exact golden encoding vector is the authoritative guard against
  /// an added field; this list names the same fields for review and tests.
  public static let allowlistedFields = [
    "selection",
    "hostID",
    "endpointOrigin",
    "hostIdentityFingerprint",
    "tlsSPKIFingerprint",
    "pairingSessionID",
    "bootstrapSecret",
    "expiresAtEpochSeconds",
  ]

  /// Placeholder substituted for the one-time secret in reflected output.
  public static let redactedSecretMarker = "redacted"

  /// The canonical, injective byte encoding presented by the QR code.
  public func canonicalEncoding() -> Data {
    var encoder = CanonicalStatementEncoder(domain: .pairingQRPayload)
    encoder.appendSelection(selection)
    encoder.appendUUID(hostID)
    encoder.appendText(endpointOrigin.normalized)
    encoder.appendVariableBytes(hostIdentityFingerprint)
    encoder.appendVariableBytes(tlsSPKIFingerprint)
    encoder.appendUUID(pairingSessionID)
    encoder.appendVariableBytes(bootstrapSecret)
    encoder.appendUInt64(expiresAtEpochSeconds)
    return encoder.encodedBytes
  }
}

extension PairingQRPayload: CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  /// Redacted: the payload carries the single-use bootstrap secret.
  public var description: String { "PairingQRPayload(redacted)" }
  public var debugDescription: String { description }

  /// Names every allowlisted field so review and tests can enumerate them,
  /// while substituting a placeholder for the secret so `dump` and other
  /// reflection paths cannot surface it.
  public var customMirror: Mirror {
    Mirror(
      self,
      children: [
        "selection": selection,
        "hostID": hostID,
        "endpointOrigin": endpointOrigin,
        "hostIdentityFingerprint": hostIdentityFingerprint,
        "tlsSPKIFingerprint": tlsSPKIFingerprint,
        "pairingSessionID": pairingSessionID,
        "bootstrapSecret": Self.redactedSecretMarker,
        "expiresAtEpochSeconds": expiresAtEpochSeconds,
      ]
    )
  }
}
