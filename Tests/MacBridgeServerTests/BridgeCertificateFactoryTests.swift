import CompanionCrypto
import CryptoKit
import Foundation
import X509
import XCTest

@testable import MacBridgeServer

final class BridgeCertificateFactoryTests: XCTestCase {
  /// Fixed issuance instant: 2026-08-01 00:00:00 UTC.
  private let issuedAt = Date(timeIntervalSince1970: 1_785_542_400)
  private let day: TimeInterval = 24 * 60 * 60

  private func assertThrows<T>(
    _ expected: BridgeCertificateError,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> T
  ) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
      XCTAssertEqual(error as? BridgeCertificateError, expected, file: file, line: line)
    }
  }

  // MARK: - Deterministic profile fields

  func testSelfSignedCertificateMatchesContentNeutralProfile() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    let certificate = material.certificate

    let expectedName = try DistinguishedName {
      CommonName(BridgeCertificateProfile.subjectCommonName)
    }
    XCTAssertEqual(certificate.subject, expectedName)
    XCTAssertEqual(certificate.issuer, expectedName)
    XCTAssertEqual(certificate.signatureAlgorithm, .ecdsaWithSHA256)

    let sans = try XCTUnwrap(certificate.extensions.subjectAlternativeNames)
    XCTAssertEqual(
      Array(sans), [.dnsName(BridgeCertificateProfile.subjectAlternativeDNSName)])

    let keyUsage = try XCTUnwrap(certificate.extensions.keyUsage)
    XCTAssertTrue(keyUsage.digitalSignature)
    XCTAssertFalse(keyUsage.keyCertSign)
    XCTAssertFalse(keyUsage.keyEncipherment)

    let extendedKeyUsage = try XCTUnwrap(certificate.extensions.extendedKeyUsage)
    XCTAssertEqual(Array(extendedKeyUsage), [.serverAuth])

    let basicConstraints = try XCTUnwrap(certificate.extensions.basicConstraints)
    XCTAssertEqual(basicConstraints, .notCertificateAuthority)
  }

  func testValidityIsExactlyThirtyDaysFromInjectedClock() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    XCTAssertEqual(material.notValidBefore, issuedAt)
    XCTAssertEqual(material.notValidAfter, issuedAt.addingTimeInterval(30 * day))
    XCTAssertEqual(
      material.notValidAfter.timeIntervalSince(material.notValidBefore),
      BridgeCertificateProfile.validityDuration
    )
  }

  func testCertificateSPKIBindsToIdentityKey() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    XCTAssertEqual(material.spkiDER, identity.spkiDER)
    XCTAssertEqual(material.spkiFingerprint, identity.spkiFingerprint)
    XCTAssertEqual(
      material.spkiFingerprint,
      try SPKIFingerprint.fingerprint(x963PublicKey: identity.publicKeyX963)
    )
  }

  func testHostRoleIdentityIsRejected() throws {
    let identity = try ServerTestFixtures.hostIdentity()
    assertThrows(.wrongIdentityRole) {
      try BridgeCertificateFactory.makeSelfSigned(identity: identity, currentDate: self.issuedAt)
    }
  }

  func testInvalidValidityIntervalIsRejected() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    assertThrows(.invalidValidityInterval) {
      try BridgeCertificateFactory.makeCertificate(
        identity: identity,
        notValidBefore: self.issuedAt,
        notValidAfter: self.issuedAt
      )
    }
  }

  // MARK: - Same-key renewal and SPKI continuity

  func testRenewalPreservesSPKIWithFreshValidity() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let original = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    let renewalDate = issuedAt.addingTimeInterval(20 * day)
    let renewed = try BridgeCertificateFactory.renew(
      original, identity: identity, currentDate: renewalDate)

    XCTAssertEqual(renewed.spkiFingerprint, original.spkiFingerprint)
    XCTAssertEqual(renewed.spkiDER, original.spkiDER)
    XCTAssertEqual(renewed.notValidBefore, renewalDate)
    XCTAssertEqual(renewed.notValidAfter, renewalDate.addingTimeInterval(30 * day))
    XCTAssertNotEqual(
      renewed.certificate.serialNumber, original.certificate.serialNumber)
  }

  func testRenewalWithDifferentKeyFailsClosed() throws {
    let original = try BridgeCertificateFactory.makeSelfSigned(
      identity: try ServerTestFixtures.tlsIdentity(), currentDate: issuedAt)
    let otherBackend = FakeSecureIdentityBackend()
    let otherIdentity = try ServerTestFixtures.store(backend: otherBackend).create(role: .tls)
    assertThrows(.spkiMismatch) {
      try BridgeCertificateFactory.renew(
        original, identity: otherIdentity, currentDate: self.issuedAt.addingTimeInterval(20 * day)
      )
    }
  }

  func testNewKeyChangesSPKIFingerprint() throws {
    let first = try BridgeCertificateFactory.makeSelfSigned(
      identity: try ServerTestFixtures.tlsIdentity(), currentDate: issuedAt)
    let otherBackend = FakeSecureIdentityBackend()
    let second = try BridgeCertificateFactory.makeSelfSigned(
      identity: try ServerTestFixtures.store(backend: otherBackend).create(role: .tls),
      currentDate: issuedAt
    )
    XCTAssertNotEqual(first.spkiFingerprint, second.spkiFingerprint)
  }

  // MARK: - Renewal-due clock logic

  func testRenewalIsNotDueBeforeTwoThirdsLifetime() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    XCTAssertFalse(BridgeCertificateFactory.isRenewalDue(for: material, at: issuedAt))
    XCTAssertFalse(
      BridgeCertificateFactory.isRenewalDue(
        for: material, at: issuedAt.addingTimeInterval(19 * day)))
    XCTAssertFalse(
      BridgeCertificateFactory.isRenewalDue(
        for: material, at: issuedAt.addingTimeInterval(20 * day - 1)))
  }

  func testRenewalIsDueFromTwoThirdsLifetimeOnward() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    XCTAssertTrue(
      BridgeCertificateFactory.isRenewalDue(
        for: material, at: issuedAt.addingTimeInterval(20 * day)))
    XCTAssertTrue(
      BridgeCertificateFactory.isRenewalDue(
        for: material, at: issuedAt.addingTimeInterval(29 * day)))
    XCTAssertTrue(
      BridgeCertificateFactory.isRenewalDue(
        for: material, at: issuedAt.addingTimeInterval(45 * day)))
  }

  // MARK: - Platform assembly

  func testSecCertificateAssemblyCarriesIdentityPublicKey() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    let secCertificate = try BridgeTLSIdentityAssembly.makeSecCertificate(from: material)
    let certificateKey = try XCTUnwrap(SecCertificateCopyKey(secCertificate))
    let x963 = try XCTUnwrap(SecKeyCopyExternalRepresentation(certificateKey, nil) as Data?)
    XCTAssertEqual(x963, identity.publicKeyX963)
  }

  func testSecIdentityAssemblyRequiresKeychainBackedKey() throws {
    let identity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: identity, currentDate: issuedAt)
    assertThrows(.assemblyFailed) {
      try BridgeTLSIdentityAssembly.makeSecIdentity(material: material, identity: identity)
    }
  }

  func testSecIdentityAssemblyRejectsWrongRoleAndWrongKey() throws {
    let tlsIdentity = try ServerTestFixtures.tlsIdentity()
    let material = try BridgeCertificateFactory.makeSelfSigned(
      identity: tlsIdentity, currentDate: issuedAt)
    let hostIdentity = try ServerTestFixtures.hostIdentity()
    assertThrows(.wrongIdentityRole) {
      try BridgeTLSIdentityAssembly.makeSecIdentity(material: material, identity: hostIdentity)
    }
    let otherBackend = FakeSecureIdentityBackend()
    let otherTLS = try ServerTestFixtures.store(backend: otherBackend).create(role: .tls)
    assertThrows(.spkiMismatch) {
      try BridgeTLSIdentityAssembly.makeSecIdentity(material: material, identity: otherTLS)
    }
  }
}
