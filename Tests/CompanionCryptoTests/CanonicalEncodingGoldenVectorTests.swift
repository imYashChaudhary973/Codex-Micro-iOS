import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

final class CanonicalEncodingGoldenVectorTests: XCTestCase {
  func testPairingTranscriptGoldenEncoding() throws {
    let transcript = try CryptoFixtures.pairingTranscript()
    XCTAssertEqual(transcript.canonicalEncoding().hexFixture, GoldenVectors.pairingEncodingHex)
    XCTAssertEqual(transcript.canonicalHash().hexFixture, GoldenVectors.pairingHashHex)
  }

  func testSessionTranscriptGoldenEncoding() throws {
    let transcript = try CryptoFixtures.sessionTranscript()
    XCTAssertEqual(transcript.canonicalEncoding().hexFixture, GoldenVectors.sessionEncodingHex)
    XCTAssertEqual(transcript.canonicalHash().hexFixture, GoldenVectors.sessionHashHex)
  }

  func testSessionAuthenticationStatementGoldenEncoding() throws {
    let statement = try CryptoFixtures.sessionAuthenticationStatement()
    XCTAssertEqual(
      statement.canonicalEncoding().hexFixture, GoldenVectors.sessionAuthStatementEncodingHex)
    XCTAssertEqual(
      statement.canonicalHash().hexFixture, GoldenVectors.sessionAuthStatementHashHex)
  }

  func testRotationStatementGoldenEncoding() throws {
    let statement = try CryptoFixtures.rotationStatement()
    XCTAssertEqual(statement.canonicalEncoding().hexFixture, GoldenVectors.rotationEncodingHex)
  }

  func testEveryStatementLeadsWithVersionAndDomain() throws {
    let cases: [(CanonicalStatementDomain, Data)] = [
      (.pairingQRPayload, try PairingFixtures.qrPayload().canonicalEncoding()),
      (.pairingTranscript, try CryptoFixtures.pairingTranscript().canonicalEncoding()),
      (.sessionTranscript, try CryptoFixtures.sessionTranscript().canonicalEncoding()),
      (
        .sessionAuthenticationStatement,
        try CryptoFixtures.sessionAuthenticationStatement().canonicalEncoding()
      ),
      (.rotationStatement, try CryptoFixtures.rotationStatement().canonicalEncoding()),
    ]
    for (domain, encoding) in cases {
      let domainBytes = Data(domain.rawValue.utf8)
      XCTAssertEqual(encoding[0], CanonicalStatementVersion.current)
      XCTAssertEqual(encoding[1], 0)
      XCTAssertEqual(Int(encoding[2]), domainBytes.count)
      XCTAssertEqual(encoding.subdata(in: 3..<(3 + domainBytes.count)), domainBytes)
    }
  }

  func testDomainSeparatorsAreDistinctASCII() {
    let domains = CanonicalStatementDomain.allCases.map(\.rawValue)
    XCTAssertEqual(Set(domains).count, domains.count)
    XCTAssertEqual(domains.count, 8)
    for domain in domains {
      XCTAssertTrue(domain.allSatisfy(\.isASCII))
      XCTAssertTrue(domain.hasSuffix("/v1"))
    }
  }

  func testOptionalFieldsEncodeExplicitPresenceBytes() {
    var absent = CanonicalStatementEncoder(domain: .rotationStatement)
    absent.appendOptionalVariableBytes(nil)
    XCTAssertEqual(absent.encodedBytes.last, 0x00)

    var present = CanonicalStatementEncoder(domain: .rotationStatement)
    present.appendOptionalVariableBytes(Data([0xAB, 0xCD]))
    XCTAssertEqual(present.encodedBytes.suffix(5), Data([0x01, 0x00, 0x02, 0xAB, 0xCD]))
  }

  func testTextFieldsUseUTF8ByteLengthPrefixes() {
    var encoder = CanonicalStatementEncoder(domain: .pairingTranscript)
    let prefixCount = encoder.encodedBytes.count
    encoder.appendText("π")
    let field = encoder.encodedBytes.subdata(in: prefixCount..<encoder.encodedBytes.count)
    XCTAssertEqual(field, Data([0x00, 0x02, 0xCF, 0x80]))
  }

  func testIntegersEncodeFixedWidthBigEndian() {
    var encoder = CanonicalStatementEncoder(domain: .sessionTranscript)
    let prefixCount = encoder.encodedBytes.count
    encoder.appendUInt64(0x0102_0304_0506_0708)
    let field = encoder.encodedBytes.subdata(in: prefixCount..<encoder.encodedBytes.count)
    XCTAssertEqual(field, Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
  }

  func testIndependentlyBuiltTranscriptsAreByteIdentical() throws {
    let deviceSide = try CryptoFixtures.pairingTranscript()
    let hostSide = try CryptoFixtures.pairingTranscript()
    XCTAssertEqual(deviceSide.canonicalEncoding(), hostSide.canonicalEncoding())

    let clientSession = try CryptoFixtures.sessionTranscript()
    let serverSession = try CryptoFixtures.sessionTranscript()
    XCTAssertEqual(clientSession.canonicalEncoding(), serverSession.canonicalEncoding())
  }

  func testEveryTranscriptFieldMutationChangesTheEncoding() throws {
    let pairingBaseline = try CryptoFixtures.pairingTranscript().canonicalEncoding()
    for (field, mutated) in try CryptoFixtures.mutatedPairingTranscripts() {
      XCTAssertNotEqual(mutated.canonicalEncoding(), pairingBaseline, "pairing field \(field)")
    }

    let sessionBaseline = try CryptoFixtures.sessionTranscript().canonicalEncoding()
    for (field, mutated) in try CryptoFixtures.mutatedSessionTranscripts() {
      XCTAssertNotEqual(mutated.canonicalEncoding(), sessionBaseline, "session field \(field)")
    }

    let rotationBaseline = try CryptoFixtures.rotationStatement().canonicalEncoding()
    for (field, mutated) in try CryptoFixtures.mutatedRotationStatements() {
      XCTAssertNotEqual(mutated.canonicalEncoding(), rotationBaseline, "rotation field \(field)")
    }
  }

  func testTranscriptInitRejectsOutOfBoundsFields() {
    XCTAssertThrowsError(
      try CryptoFixtures.pairingTranscript(bootstrapSecret: Data(repeating: 0xB5, count: 31)))
    XCTAssertThrowsError(
      try CryptoFixtures.pairingTranscript(deviceNonce: Data(repeating: 0xD1, count: 33)))
    XCTAssertThrowsError(
      try CryptoFixtures.pairingTranscript(devicePublicKey: Data(repeating: 0x04, count: 64)))
    XCTAssertThrowsError(try CryptoFixtures.pairingTranscript(endpointOrigin: ""))
    XCTAssertThrowsError(
      try CryptoFixtures.pairingTranscript(endpointOrigin: String(repeating: "a", count: 129)))
    XCTAssertThrowsError(
      try CryptoFixtures.pairingTranscript(hostTLSSPKIFingerprint: Data(count: 31)))
    XCTAssertThrowsError(
      try CryptoFixtures.sessionTranscript(
        deviceEphemeralPublicKey: Data(repeating: 0x04, count: 66)))
    XCTAssertThrowsError(
      try CryptoFixtures.sessionTranscript(hostNonce: Data(repeating: 0xF7, count: 31)))
  }
}
