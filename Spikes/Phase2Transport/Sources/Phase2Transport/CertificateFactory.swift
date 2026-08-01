import Foundation
import Security
import X509

public enum CertificateFactoryError: Error, Equatable {
  case incorrectIdentityRole
  case invalidValidity
  case identityConstructionFailed
  case publicKeyMismatch
  case signatureInvalid
}

public struct TLSCertificateMaterial: @unchecked Sendable {
  public let certificate: Certificate
  public let secCertificate: SecCertificate
  public let secIdentity: SecIdentity
  public let spkiDER: Data
  public let spkiSHA256: Data

  fileprivate init(
    certificate: Certificate,
    secCertificate: SecCertificate,
    secIdentity: SecIdentity,
    spkiDER: Data,
    spkiSHA256: Data
  ) {
    self.certificate = certificate
    self.secCertificate = secCertificate
    self.secIdentity = secIdentity
    self.spkiDER = spkiDER
    self.spkiSHA256 = spkiSHA256
  }
}

public enum ContentNeutralCertificateFactory {
  public static let subjectCommonName = "Phase 2 Transport Spike"
  public static let subjectAlternativeName = "phase2-spike.invalid"

  public static func makeSelfSigned(
    identity: KeychainIdentity,
    notValidBefore: Date,
    notValidAfter: Date
  ) throws -> TLSCertificateMaterial {
    guard identity.role == .tls else {
      throw CertificateFactoryError.incorrectIdentityRole
    }
    guard notValidBefore < notValidAfter else {
      throw CertificateFactoryError.invalidValidity
    }

    let privateKey = try Certificate.PrivateKey(identity.privateKey)
    let name = try DistinguishedName {
      CommonName(Self.subjectCommonName)
    }
    let extensions = try Certificate.Extensions {
      Critical(BasicConstraints.notCertificateAuthority)
      Critical(KeyUsage(digitalSignature: true))
      try ExtendedKeyUsage([.serverAuth])
      SubjectAlternativeNames([.dnsName(Self.subjectAlternativeName)])
    }
    let certificate = try Certificate(
      version: .v3,
      serialNumber: Certificate.SerialNumber(),
      publicKey: privateKey.publicKey,
      notValidBefore: notValidBefore,
      notValidAfter: notValidAfter,
      issuer: name,
      subject: name,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: extensions,
      issuerPrivateKey: privateKey
    )
    guard certificate.publicKey.isValidSignature(certificate.signature, for: certificate) else {
      throw CertificateFactoryError.signatureInvalid
    }
    let point = Data(certificate.publicKey.subjectPublicKeyInfoBytes)
    let certificateSPKI = try P256SPKI.der(uncompressedPoint: point)
    guard P256SPKI.matches(certificateSPKI, identity.spkiDER) else {
      throw CertificateFactoryError.publicKeyMismatch
    }

    let secCertificate = try SecCertificate.makeWithCertificate(certificate)
    guard let certificateKey = SecCertificateCopyKey(secCertificate) else {
      throw CertificateFactoryError.publicKeyMismatch
    }
    let secCertificateSPKI = try P256SPKI.der(publicKey: certificateKey)
    guard P256SPKI.matches(secCertificateSPKI, identity.spkiDER) else {
      throw CertificateFactoryError.publicKeyMismatch
    }
    guard let secIdentity = SecIdentityCreate(nil, secCertificate, identity.privateKey) else {
      throw CertificateFactoryError.identityConstructionFailed
    }

    return TLSCertificateMaterial(
      certificate: certificate,
      secCertificate: secCertificate,
      secIdentity: secIdentity,
      spkiDER: certificateSPKI,
      spkiSHA256: P256SPKI.sha256(certificateSPKI)
    )
  }
}
