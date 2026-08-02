import CompanionCrypto
import CryptoKit
import Foundation
import Security
import X509

/// Closed certificate-lifecycle failure vocabulary. Carries no content.
public enum BridgeCertificateError: Error, Equatable, Sendable {
  /// Assembling the platform `SecCertificate`/`SecIdentity` failed.
  case assemblyFailed
  /// The requested validity interval is empty or inverted.
  case invalidValidityInterval
  /// The certificate public key does not match the TLS identity key, or a
  /// renewal would change the pinned SPKI. Fails closed (ADR §7).
  case spkiMismatch
  /// The self-signature did not verify after issuance.
  case signatureInvalid
  /// The operation requires the `.tls` identity role.
  case wrongIdentityRole
}

/// Fixed content-neutral certificate profile (ADR §7).
///
/// Every field is a static constant: no host, device, user, or project
/// value ever reaches a certificate.
public enum BridgeCertificateProfile {
  /// Fixed static subject common name.
  public static let subjectCommonName = "codex-micro-bridge"
  /// Fixed static subject-alternative DNS name under the reserved
  /// `.invalid` TLD.
  public static let subjectAlternativeDNSName = "codex-micro-bridge.invalid"
  /// Certificate lifetime: exactly 30 days.
  public static let validityDuration: TimeInterval = 30 * 24 * 60 * 60
  /// Renewal becomes due at two-thirds of the certificate lifetime.
  public static let renewalLifetimeFraction = 2.0 / 3.0
}

/// An issued content-neutral TLS certificate plus its pinned SPKI
/// material. Clients pin ``spkiFingerprint``, never certificate bytes, so
/// same-key renewal is transparent (ADR §7).
public struct BridgeTLSCertificate: Sendable {
  /// The issued X.509 certificate.
  public let certificate: Certificate
  /// The P-256 SubjectPublicKeyInfo DER of the certificate key.
  public let spkiDER: Data
  /// The SHA-256 SPKI fingerprint clients pin.
  public let spkiFingerprint: Data
  /// Start of validity.
  public let notValidBefore: Date
  /// End of validity.
  public let notValidAfter: Date
}

/// Content-neutral self-signed certificate issuance and same-key renewal
/// for the `.tls` identity (ADR §7).
///
/// Signing goes through the identity backend: the production path signs
/// with the non-exportable Secure Enclave `SecKey`; the test path signs
/// with an in-memory CryptoKit key behind the same seam. All time inputs
/// are injected — nothing reads the wall clock.
public enum BridgeCertificateFactory {
  /// Issues a content-neutral self-signed certificate for the `.tls`
  /// identity valid for exactly 30 days from `currentDate`.
  ///
  /// Profile per ADR §7: ECDSA P-256/SHA-256, fixed subject and SAN,
  /// critical `digitalSignature` key usage, `serverAuth` EKU, critical
  /// not-a-CA basic constraints, random non-identifying serial. After
  /// issuance the self-signature and the SPKI binding to the identity key
  /// are verified; any mismatch fails closed.
  public static func makeSelfSigned(
    identity: BridgeIdentity,
    currentDate: Date
  ) throws -> BridgeTLSCertificate {
    try makeCertificate(
      identity: identity,
      notValidBefore: currentDate,
      notValidAfter: currentDate.addingTimeInterval(BridgeCertificateProfile.validityDuration)
    )
  }

  /// Renews `existing` with the **same** TLS key at `currentDate`.
  ///
  /// Renewal preserves the pinned SPKI: the existing certificate, the
  /// identity key, and the freshly issued certificate must all carry the
  /// identical fingerprint, otherwise ``BridgeCertificateError/spkiMismatch``
  /// surfaces and nothing is issued. Key *rotation* is a different
  /// operation that requires a host-signed rotation statement.
  public static func renew(
    _ existing: BridgeTLSCertificate,
    identity: BridgeIdentity,
    currentDate: Date
  ) throws -> BridgeTLSCertificate {
    guard constantTimeEquals(existing.spkiFingerprint, identity.spkiFingerprint) else {
      throw BridgeCertificateError.spkiMismatch
    }
    let renewed = try makeSelfSigned(identity: identity, currentDate: currentDate)
    guard constantTimeEquals(renewed.spkiFingerprint, existing.spkiFingerprint) else {
      throw BridgeCertificateError.spkiMismatch
    }
    return renewed
  }

  /// Whether same-key renewal is due at `date`: true from two-thirds of
  /// the certificate lifetime onward (about day 20 of 30, ADR §7).
  public static func isRenewalDue(for certificate: BridgeTLSCertificate, at date: Date) -> Bool {
    let lifetime = certificate.notValidAfter.timeIntervalSince(certificate.notValidBefore)
    let threshold = certificate.notValidBefore.addingTimeInterval(
      lifetime * BridgeCertificateProfile.renewalLifetimeFraction)
    return date >= threshold
  }

  static func makeCertificate(
    identity: BridgeIdentity,
    notValidBefore: Date,
    notValidAfter: Date
  ) throws -> BridgeTLSCertificate {
    guard identity.role == .tls else {
      throw BridgeCertificateError.wrongIdentityRole
    }
    guard notValidBefore < notValidAfter else {
      throw BridgeCertificateError.invalidValidityInterval
    }

    let signer = try identity.certificateSigner()
    let name = try DistinguishedName {
      CommonName(BridgeCertificateProfile.subjectCommonName)
    }
    let extensions = try Certificate.Extensions {
      Critical(BasicConstraints.notCertificateAuthority)
      Critical(KeyUsage(digitalSignature: true))
      try ExtendedKeyUsage([.serverAuth])
      SubjectAlternativeNames([
        .dnsName(BridgeCertificateProfile.subjectAlternativeDNSName)
      ])
    }
    let certificate = try Certificate(
      version: .v3,
      serialNumber: Certificate.SerialNumber(),
      publicKey: signer.publicKey,
      notValidBefore: notValidBefore,
      notValidAfter: notValidAfter,
      issuer: name,
      subject: name,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: extensions,
      issuerPrivateKey: signer
    )
    guard certificate.publicKey.isValidSignature(certificate.signature, for: certificate) else {
      throw BridgeCertificateError.signatureInvalid
    }

    let point = Data(certificate.publicKey.subjectPublicKeyInfoBytes)
    guard let spkiDER = try? SPKIFingerprint.subjectPublicKeyInfoDER(x963PublicKey: point),
      constantTimeEquals(spkiDER, identity.spkiDER)
    else {
      throw BridgeCertificateError.spkiMismatch
    }

    return BridgeTLSCertificate(
      certificate: certificate,
      spkiDER: spkiDER,
      spkiFingerprint: Data(SHA256.hash(data: spkiDER)),
      notValidBefore: notValidBefore,
      notValidAfter: notValidAfter
    )
  }
}

/// Platform `SecCertificate`/`SecIdentity` assembly for serving the
/// certificate through Network.framework TLS (consumed by the Step 2.7
/// listener; requires the Keychain-backed identity).
public enum BridgeTLSIdentityAssembly {
  /// Converts the issued certificate to a `SecCertificate`.
  public static func makeSecCertificate(
    from material: BridgeTLSCertificate
  ) throws -> SecCertificate {
    guard let secCertificate = try? SecCertificate.makeWithCertificate(material.certificate)
    else {
      throw BridgeCertificateError.assemblyFailed
    }
    return secCertificate
  }

  /// Assembles the serving `SecIdentity` from the issued certificate and
  /// the Secure Enclave `.tls` identity.
  ///
  /// The certificate's pinned SPKI must match the identity key and the
  /// identity must be Keychain-backed; the resulting `SecIdentity` binds
  /// the certificate to the non-exportable private key. The
  /// `SecCertificate` round trip re-verifies the public key match.
  public static func makeSecIdentity(
    material: BridgeTLSCertificate,
    identity: BridgeIdentity
  ) throws -> SecIdentity {
    guard identity.role == .tls else {
      throw BridgeCertificateError.wrongIdentityRole
    }
    guard constantTimeEquals(material.spkiFingerprint, identity.spkiFingerprint) else {
      throw BridgeCertificateError.spkiMismatch
    }
    guard let enclaveKey = identity.key as? SecureEnclaveIdentityKey else {
      throw BridgeCertificateError.assemblyFailed
    }
    let secCertificate = try makeSecCertificate(from: material)
    guard let certificateKey = SecCertificateCopyKey(secCertificate),
      let certificateX963 = SecKeyCopyExternalRepresentation(certificateKey, nil) as Data?,
      constantTimeEquals(certificateX963, identity.publicKeyX963)
    else {
      throw BridgeCertificateError.spkiMismatch
    }
    guard let secIdentity = SecIdentityCreate(nil, secCertificate, enclaveKey.secKey) else {
      throw BridgeCertificateError.assemblyFailed
    }
    return secIdentity
  }
}
