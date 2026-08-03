import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

final class TranscriptSignatureTests: XCTestCase {
  func testPairingTranscriptSignatureRoundTripAcrossRoles() throws {
    let hostSide = try CryptoFixtures.pairingTranscript()
    let signature = try SecureTranscriptSignature.sign(
      hostSide.canonicalEncoding(), using: CryptoFixtures.hostSigningKey)

    let deviceSide = try CryptoFixtures.pairingTranscript()
    let hostPublicKey = try SecureP256KeyEncoding.signingPublicKey(
      fromX963: CryptoFixtures.hostPublicKeyX963)
    XCTAssertTrue(
      SecureTranscriptSignature.isValid(
        signature, for: deviceSide.canonicalEncoding(), publicKey: hostPublicKey))
  }

  func testSessionTranscriptSignatureRoundTripAcrossRoles() throws {
    let deviceSide = try CryptoFixtures.sessionTranscript()
    let signature = try SecureTranscriptSignature.sign(
      deviceSide.canonicalEncoding(), using: CryptoFixtures.deviceSigningKey)

    let hostSide = try CryptoFixtures.sessionTranscript()
    let devicePublicKey = try SecureP256KeyEncoding.signingPublicKey(
      fromX963: CryptoFixtures.devicePublicKeyX963)
    XCTAssertTrue(
      SecureTranscriptSignature.isValid(
        signature, for: hostSide.canonicalEncoding(), publicKey: devicePublicKey))
  }

  func testGoldenHostSignatureVerifies() throws {
    XCTAssertTrue(
      SecureTranscriptSignature.isValid(
        Data(hexFixture: GoldenVectors.hostPairingSignatureHex),
        for: try CryptoFixtures.pairingTranscript().canonicalEncoding(),
        publicKey: CryptoFixtures.hostSigningKey.publicKey
      ))
  }

  func testSignatureIsExactlySixtyFourRawBytes() throws {
    let signature = try SecureTranscriptSignature.sign(
      CryptoFixtures.pairingTranscript().canonicalEncoding(),
      using: CryptoFixtures.hostSigningKey)
    XCTAssertEqual(signature.count, 64)
    XCTAssertEqual(SecureTranscriptSignature.byteCount, 64)
  }

  func testNonRawSignatureLengthsAreRejected() throws {
    let statement = try CryptoFixtures.pairingTranscript().canonicalEncoding()
    let raw = try SecureTranscriptSignature.sign(statement, using: CryptoFixtures.hostSigningKey)
    let publicKey = CryptoFixtures.hostSigningKey.publicKey

    let derSignature = try P256.Signing.ECDSASignature(rawRepresentation: raw).derRepresentation
    XCTAssertFalse(
      SecureTranscriptSignature.isValid(derSignature, for: statement, publicKey: publicKey))
    XCTAssertFalse(
      SecureTranscriptSignature.isValid(raw + Data([0x00]), for: statement, publicKey: publicKey))
    XCTAssertFalse(
      SecureTranscriptSignature.isValid(raw.dropLast(), for: statement, publicKey: publicKey))
    XCTAssertFalse(SecureTranscriptSignature.isValid(Data(), for: statement, publicKey: publicKey))
  }

  func testTamperedSignatureIsRejected() throws {
    let statement = try CryptoFixtures.pairingTranscript().canonicalEncoding()
    let raw = try SecureTranscriptSignature.sign(statement, using: CryptoFixtures.hostSigningKey)
    XCTAssertFalse(
      SecureTranscriptSignature.isValid(
        CryptoFixtures.mutated(raw, at: 10),
        for: statement,
        publicKey: CryptoFixtures.hostSigningKey.publicKey
      ))
  }

  func testWrongSignerIsRejected() throws {
    let statement = try CryptoFixtures.pairingTranscript().canonicalEncoding()
    let signature = try SecureTranscriptSignature.sign(
      statement, using: CryptoFixtures.deviceSigningKey)
    XCTAssertFalse(
      SecureTranscriptSignature.isValid(
        signature, for: statement, publicKey: CryptoFixtures.hostSigningKey.publicKey))
  }

  func testEveryPairingTranscriptFieldMutationFailsVerification() throws {
    let signature = try SecureTranscriptSignature.sign(
      CryptoFixtures.pairingTranscript().canonicalEncoding(),
      using: CryptoFixtures.hostSigningKey)
    let publicKey = CryptoFixtures.hostSigningKey.publicKey
    let mutations = try CryptoFixtures.mutatedPairingTranscripts()
    XCTAssertEqual(mutations.count, 12)
    for (field, mutated) in mutations {
      XCTAssertFalse(
        SecureTranscriptSignature.isValid(
          signature, for: mutated.canonicalEncoding(), publicKey: publicKey),
        "mutated pairing field \(field) must fail verification"
      )
    }
  }

  func testEverySessionTranscriptFieldMutationFailsVerification() throws {
    let signature = try SecureTranscriptSignature.sign(
      CryptoFixtures.sessionTranscript().canonicalEncoding(),
      using: CryptoFixtures.deviceSigningKey)
    let publicKey = CryptoFixtures.deviceSigningKey.publicKey
    let mutations = try CryptoFixtures.mutatedSessionTranscripts()
    XCTAssertEqual(mutations.count, 10)
    for (field, mutated) in mutations {
      XCTAssertFalse(
        SecureTranscriptSignature.isValid(
          signature, for: mutated.canonicalEncoding(), publicKey: publicKey),
        "mutated session field \(field) must fail verification"
      )
    }
  }

  func testEverySessionAuthStatementFieldMutationFailsVerification() throws {
    let signature = try SecureTranscriptSignature.sign(
      CryptoFixtures.sessionAuthenticationStatement().canonicalEncoding(),
      using: CryptoFixtures.deviceSigningKey)
    let publicKey = CryptoFixtures.deviceSigningKey.publicKey
    let mutations = try CryptoFixtures.mutatedSessionAuthStatements()
    XCTAssertEqual(mutations.count, 7)
    for (field, mutated) in mutations {
      XCTAssertFalse(
        SecureTranscriptSignature.isValid(
          signature, for: mutated.canonicalEncoding(), publicKey: publicKey),
        "mutated statement field \(field) must fail verification"
      )
    }
  }

  func testSignatureFromOneDomainNeverVerifiesAnother() throws {
    let signature = try SecureTranscriptSignature.sign(
      CryptoFixtures.pairingTranscript().canonicalEncoding(),
      using: CryptoFixtures.hostSigningKey)
    XCTAssertFalse(
      SecureTranscriptSignature.isValid(
        signature,
        for: try CryptoFixtures.sessionTranscript().canonicalEncoding(),
        publicKey: CryptoFixtures.hostSigningKey.publicKey
      ))
  }
}
