import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

final class RotationStatementTests: XCTestCase {
  private let withinValidity: UInt64 = 1_754_040_000

  private func verify(
    statement: SecureRotationStatement,
    signature: Data,
    pinned: Data? = nil,
    lastAcceptedGeneration: UInt64 = 0,
    at time: UInt64? = nil
  ) throws {
    try SecureRotationVerifier.verify(
      statement: statement,
      signature: signature,
      hostPublicKey: CryptoFixtures.hostSigningKey.publicKey,
      pinnedCurrentSPKIFingerprint: pinned ?? CryptoFixtures.tlsCurrentSPKIFingerprint,
      lastAcceptedGeneration: lastAcceptedGeneration,
      atEpochSeconds: time ?? withinValidity
    )
  }

  func testCanonicalEncodingDecodeRoundTrip() throws {
    let statement = try CryptoFixtures.rotationStatement()
    let decoded = try SecureRotationStatement(canonicalEncoding: statement.canonicalEncoding())
    XCTAssertEqual(decoded, statement)
  }

  func testHostSignsAndClientVerifiesGoldenStatement() throws {
    let statement = try CryptoFixtures.rotationStatement()
    let signature = try SecureRotationVerifier.sign(
      statement, using: CryptoFixtures.hostSigningKey)
    XCTAssertEqual(signature.count, 64)

    let received = try SecureRotationStatement(canonicalEncoding: statement.canonicalEncoding())
    XCTAssertNoThrow(try verify(statement: received, signature: signature))
  }

  func testRecordedGoldenSignatureVerifies() throws {
    let statement = try SecureRotationStatement(
      canonicalEncoding: Data(hexFixture: GoldenVectors.rotationEncodingHex))
    XCTAssertNoThrow(
      try verify(
        statement: statement, signature: Data(hexFixture: GoldenVectors.hostRotationSignatureHex)))
  }

  func testEveryStatementFieldMutationFailsVerification() throws {
    let signature = try SecureRotationVerifier.sign(
      CryptoFixtures.rotationStatement(), using: CryptoFixtures.hostSigningKey)
    let mutations = try CryptoFixtures.mutatedRotationStatements()
    XCTAssertEqual(mutations.count, 5)
    for (field, mutated) in mutations {
      let start = mutated.validityStartEpochSeconds
      let end = mutated.validityEndEpochSeconds
      let insideWindow = min(max(withinValidity, start), end)
      XCTAssertThrowsError(
        try verify(
          statement: mutated,
          signature: signature,
          pinned: mutated.currentSPKIFingerprint,
          at: insideWindow
        ),
        "mutated rotation field \(field) must fail verification"
      ) { error in
        XCTAssertEqual(error as? SecureRotationError, .invalidSignature)
      }
    }
  }

  func testWrongSignerIsRejected() throws {
    let statement = try CryptoFixtures.rotationStatement()
    let signature = try SecureRotationVerifier.sign(
      statement, using: CryptoFixtures.deviceSigningKey)
    XCTAssertThrowsError(try verify(statement: statement, signature: signature)) { error in
      XCTAssertEqual(error as? SecureRotationError, .invalidSignature)
    }
  }

  func testCurrentPinMismatchIsRejected() throws {
    let statement = try CryptoFixtures.rotationStatement()
    let signature = try SecureRotationVerifier.sign(statement, using: CryptoFixtures.hostSigningKey)
    XCTAssertThrowsError(
      try verify(
        statement: statement,
        signature: signature,
        pinned: CryptoFixtures.mutated(CryptoFixtures.tlsCurrentSPKIFingerprint, at: 3)
      )
    ) { error in
      XCTAssertEqual(error as? SecureRotationError, .currentPinMismatch)
    }
  }

  func testGenerationMustBeStrictlyMonotonic() throws {
    let statement = try CryptoFixtures.rotationStatement()
    let signature = try SecureRotationVerifier.sign(statement, using: CryptoFixtures.hostSigningKey)

    XCTAssertNoThrow(
      try verify(statement: statement, signature: signature, lastAcceptedGeneration: 2))
    for lastAccepted: UInt64 in [3, 4, .max] {
      XCTAssertThrowsError(
        try verify(statement: statement, signature: signature, lastAcceptedGeneration: lastAccepted)
      ) { error in
        XCTAssertEqual(error as? SecureRotationError, .nonMonotonicGeneration)
      }
    }
  }

  func testValidityIntervalIsInclusiveAndEnforced() throws {
    let statement = try CryptoFixtures.rotationStatement()
    let signature = try SecureRotationVerifier.sign(statement, using: CryptoFixtures.hostSigningKey)

    XCTAssertNoThrow(
      try verify(
        statement: statement, signature: signature, at: statement.validityStartEpochSeconds))
    XCTAssertNoThrow(
      try verify(statement: statement, signature: signature, at: statement.validityEndEpochSeconds))
    XCTAssertThrowsError(
      try verify(
        statement: statement, signature: signature, at: statement.validityStartEpochSeconds - 1)
    ) { error in
      XCTAssertEqual(error as? SecureRotationError, .notYetValid)
    }
    XCTAssertThrowsError(
      try verify(
        statement: statement, signature: signature, at: statement.validityEndEpochSeconds + 1)
    ) { error in
      XCTAssertEqual(error as? SecureRotationError, .expired)
    }
  }

  func testDecodeRejectsTrailingBytes() throws {
    let encoding = try CryptoFixtures.rotationStatement().canonicalEncoding()
    XCTAssertThrowsError(try SecureRotationStatement(canonicalEncoding: encoding + Data([0x00])))
  }

  func testDecodeRejectsTruncation() throws {
    let encoding = try CryptoFixtures.rotationStatement().canonicalEncoding()
    XCTAssertThrowsError(try SecureRotationStatement(canonicalEncoding: encoding.dropLast()))
    XCTAssertThrowsError(try SecureRotationStatement(canonicalEncoding: Data()))
    XCTAssertThrowsError(try SecureRotationStatement(canonicalEncoding: encoding.prefix(40)))
  }

  func testDecodeRejectsWrongVersion() throws {
    var encoding = try CryptoFixtures.rotationStatement().canonicalEncoding()
    encoding[0] = 0x02
    XCTAssertThrowsError(try SecureRotationStatement(canonicalEncoding: encoding))
  }

  func testDecodeRejectsForeignDomain() throws {
    let statement = try CryptoFixtures.rotationStatement()
    var foreign = CanonicalStatementEncoder(domain: .sessionTranscript)
    foreign.appendUInt64(statement.rotationGeneration)
    foreign.appendVariableBytes(statement.currentSPKIFingerprint)
    foreign.appendVariableBytes(statement.nextSPKIFingerprint)
    foreign.appendUInt64(statement.validityStartEpochSeconds)
    foreign.appendUInt64(statement.validityEndEpochSeconds)
    XCTAssertThrowsError(try SecureRotationStatement(canonicalEncoding: foreign.encodedBytes))
  }

  func testDecodeRejectsWrongFieldLength() throws {
    let encoding = try CryptoFixtures.rotationStatement().canonicalEncoding()
    // The length prefix of `currentSPKIFingerprint` sits after the version,
    // domain, and generation fields; shrinking it desynchronizes the layout.
    let lengthPrefixIndex = 1 + 2 + 33 + 8 + 1
    var patched = encoding
    patched[lengthPrefixIndex] = 31
    XCTAssertThrowsError(try SecureRotationStatement(canonicalEncoding: patched))
  }

  func testInitRejectsInvalidSemanticFields() {
    XCTAssertThrowsError(try CryptoFixtures.rotationStatement(rotationGeneration: 0))
    XCTAssertThrowsError(
      try CryptoFixtures.rotationStatement(currentSPKIFingerprint: Data(count: 31)))
    XCTAssertThrowsError(
      try CryptoFixtures.rotationStatement(
        nextSPKIFingerprint: CryptoFixtures.tlsCurrentSPKIFingerprint))
    XCTAssertThrowsError(
      try CryptoFixtures.rotationStatement(
        validityStartEpochSeconds: 2, validityEndEpochSeconds: 2))
    XCTAssertThrowsError(
      try CryptoFixtures.rotationStatement(
        validityStartEpochSeconds: 3, validityEndEpochSeconds: 2))
  }
}
