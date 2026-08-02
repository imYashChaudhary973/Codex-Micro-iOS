import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

final class SecureP256AndSPKITests: XCTestCase {
  func testX963RoundTripForBothKeyRoles() throws {
    let signing = try SecureP256KeyEncoding.signingPublicKey(
      fromX963: CryptoFixtures.hostPublicKeyX963)
    XCTAssertEqual(
      SecureP256KeyEncoding.x963Representation(of: signing), CryptoFixtures.hostPublicKeyX963)

    let agreement = try SecureP256KeyEncoding.keyAgreementPublicKey(
      fromX963: CryptoFixtures.clientEphemeralPublicKeyX963)
    XCTAssertEqual(
      SecureP256KeyEncoding.x963Representation(of: agreement),
      CryptoFixtures.clientEphemeralPublicKeyX963
    )
    XCTAssertEqual(CryptoFixtures.hostPublicKeyX963.count, 65)
    XCTAssertEqual(CryptoFixtures.hostPublicKeyX963.first, 0x04)
  }

  func testX963RejectsWrongLengths() {
    XCTAssertThrowsError(try SecureP256KeyEncoding.signingPublicKey(fromX963: Data()))
    XCTAssertThrowsError(
      try SecureP256KeyEncoding.signingPublicKey(
        fromX963: CryptoFixtures.hostPublicKeyX963.dropLast()))
    XCTAssertThrowsError(
      try SecureP256KeyEncoding.signingPublicKey(
        fromX963: CryptoFixtures.hostPublicKeyX963 + Data([0x00])))
    XCTAssertThrowsError(
      try SecureP256KeyEncoding.keyAgreementPublicKey(fromX963: Data(repeating: 0x04, count: 64)))
  }

  func testX963RejectsCompressedPointEncodings() {
    let compressed = Data([0x02]) + CryptoFixtures.hostPublicKeyX963.subdata(in: 1..<33)
    XCTAssertThrowsError(try SecureP256KeyEncoding.signingPublicKey(fromX963: compressed))

    var wrongTag = CryptoFixtures.hostPublicKeyX963
    wrongTag[0] = 0x02
    XCTAssertThrowsError(try SecureP256KeyEncoding.signingPublicKey(fromX963: wrongTag))
  }

  func testX963RejectsOffCurvePoints() {
    var offCurve = Data([0x04])
    offCurve.append(Data(repeating: 0xAB, count: 64))
    XCTAssertThrowsError(try SecureP256KeyEncoding.signingPublicKey(fromX963: offCurve))
    XCTAssertThrowsError(try SecureP256KeyEncoding.keyAgreementPublicKey(fromX963: offCurve))
  }

  func testECDHSharedSecretMatchesAcrossRoles() throws {
    let clientSecret = try SecureKeyAgreement.sharedSecret(
      privateKey: CryptoFixtures.clientEphemeralKey,
      peerPublicKeyX963: CryptoFixtures.serverEphemeralPublicKeyX963)
    let serverSecret = try SecureKeyAgreement.sharedSecret(
      privateKey: CryptoFixtures.serverEphemeralKey,
      peerPublicKeyX963: CryptoFixtures.clientEphemeralPublicKeyX963)
    XCTAssertEqual(clientSecret, serverSecret)
    XCTAssertEqual(
      clientSecret.withUnsafeBytes { Data($0) }.hexFixture, GoldenVectors.sharedSecretHex)
  }

  func testECDHRejectsInvalidPeerKey() {
    var offCurve = Data([0x04])
    offCurve.append(Data(repeating: 0xAB, count: 64))
    XCTAssertThrowsError(
      try SecureKeyAgreement.sharedSecret(
        privateKey: CryptoFixtures.clientEphemeralKey, peerPublicKeyX963: offCurve))
  }

  func testFreshEphemeralKeysAreUnique() {
    let first = SecureKeyAgreement.makeEphemeralPrivateKey()
    let second = SecureKeyAgreement.makeEphemeralPrivateKey()
    XCTAssertNotEqual(
      first.publicKey.x963Representation, second.publicKey.x963Representation)
  }

  func testSPKIFingerprintGoldenVector() throws {
    let fingerprint = try SPKIFingerprint.fingerprint(
      x963PublicKey: CryptoFixtures.devicePublicKeyX963)
    XCTAssertEqual(fingerprint.hexFixture, GoldenVectors.deviceSPKIFingerprintHex)
    XCTAssertEqual(fingerprint.count, SPKIFingerprint.byteCount)
    XCTAssertEqual(
      SPKIFingerprint.fingerprint(of: CryptoFixtures.deviceSigningKey.publicKey), fingerprint)
  }

  func testSPKIDERStructure() throws {
    let der = try SPKIFingerprint.subjectPublicKeyInfoDER(
      x963PublicKey: CryptoFixtures.devicePublicKeyX963)
    XCTAssertEqual(der.count, SPKIFingerprint.derByteCount)
    XCTAssertEqual(der.prefix(2), Data([0x30, 0x59]))
    XCTAssertEqual(der.suffix(65), CryptoFixtures.devicePublicKeyX963)
  }

  func testSPKIFingerprintIsStablePerKeyAndDistinctAcrossKeys() throws {
    let first = try SPKIFingerprint.fingerprint(x963PublicKey: CryptoFixtures.hostPublicKeyX963)
    let second = try SPKIFingerprint.fingerprint(x963PublicKey: CryptoFixtures.hostPublicKeyX963)
    XCTAssertEqual(first, second)
    XCTAssertNotEqual(
      first, try SPKIFingerprint.fingerprint(x963PublicKey: CryptoFixtures.devicePublicKeyX963))
  }

  func testSPKIFingerprintRejectsInvalidKeys() {
    XCTAssertThrowsError(try SPKIFingerprint.fingerprint(x963PublicKey: Data()))
    var offCurve = Data([0x04])
    offCurve.append(Data(repeating: 0xCD, count: 64))
    XCTAssertThrowsError(try SPKIFingerprint.fingerprint(x963PublicKey: offCurve))
  }
}
