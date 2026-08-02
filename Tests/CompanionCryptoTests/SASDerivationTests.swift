import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

final class SASDerivationTests: XCTestCase {
  func testGoldenIndicesAndDisplayString() throws {
    let sas = SecureShortAuthenticationString.derive(from: try CryptoFixtures.pairingTranscript())
    XCTAssertEqual(sas.indices, GoldenVectors.sasIndices)
    XCTAssertEqual(sas.displayString, GoldenVectors.sasDisplay)
  }

  func testIndicesAreSixElevenBitValues() throws {
    let sas = SecureShortAuthenticationString.derive(from: try CryptoFixtures.pairingTranscript())
    XCTAssertEqual(sas.indices.count, SecureShortAuthenticationString.indexCount)
    XCTAssertTrue(
      sas.indices.allSatisfy { $0 < SecureShortAuthenticationString.indexUpperBound })
    XCTAssertEqual(SecureShortAuthenticationString.derivedBitCount, 66)
    XCTAssertEqual(
      SecureShortAuthenticationString.indexCount * SecureShortAuthenticationString.bitsPerIndex,
      SecureShortAuthenticationString.derivedBitCount
    )
  }

  func testDisplayGroupsAreZeroPaddedFourDigitDecimals() throws {
    let sas = SecureShortAuthenticationString.derive(from: try CryptoFixtures.pairingTranscript())
    XCTAssertEqual(sas.displayGroups.count, 6)
    for (index, group) in zip(sas.indices, sas.displayGroups) {
      XCTAssertEqual(group.count, 4)
      XCTAssertTrue(group.allSatisfy(\.isNumber))
      XCTAssertEqual(Int(group), Int(index))
    }
    XCTAssertEqual(sas.displayString, sas.displayGroups.joined(separator: "-"))
  }

  func testBothEndpointsDeriveTheSameSAS() throws {
    let deviceSide = SecureShortAuthenticationString.derive(
      from: try CryptoFixtures.pairingTranscript())
    let hostSide = try SecureShortAuthenticationString.derive(
      fromTranscriptHash: CryptoFixtures.pairingTranscript().canonicalHash())
    XCTAssertEqual(deviceSide, hostSide)
  }

  func testEveryPairingTranscriptFieldMutationChangesTheSAS() throws {
    let baseline = SecureShortAuthenticationString.derive(
      from: try CryptoFixtures.pairingTranscript())
    for (field, mutated) in try CryptoFixtures.mutatedPairingTranscripts() {
      XCTAssertNotEqual(
        SecureShortAuthenticationString.derive(from: mutated),
        baseline,
        "mutated pairing field \(field) must change the SAS"
      )
    }
  }

  func testBitSlicingConsumesExactlySixtySixBits() {
    let allOnes = SecureShortAuthenticationString.unpackIndices(Data(repeating: 0xFF, count: 9))
    XCTAssertEqual(allOnes, [2047, 2047, 2047, 2047, 2047, 2047])

    let allZeros = SecureShortAuthenticationString.unpackIndices(Data(count: 9))
    XCTAssertEqual(allZeros, [0, 0, 0, 0, 0, 0])

    // The first index is the top 11 bits of the stream: 0x80 0x10 -> 0b10000000000.
    var leadingBit = Data(count: 9)
    leadingBit[0] = 0x80
    leadingBit[1] = 0x10
    XCTAssertEqual(SecureShortAuthenticationString.unpackIndices(leadingBit).first, 1024)

    // The trailing 6 bits of the 72-bit output are never consumed.
    let trailingBits = Data(repeating: 0xAB, count: 9)
    var flippedTail = trailingBits
    flippedTail[8] = trailingBits[8] ^ 0x3F
    XCTAssertEqual(
      SecureShortAuthenticationString.unpackIndices(trailingBits),
      SecureShortAuthenticationString.unpackIndices(flippedTail)
    )

    // Bit 66 (the highest bit the last index consumes) must still matter.
    var consumedBit = trailingBits
    consumedBit[8] = trailingBits[8] ^ 0x40
    XCTAssertNotEqual(
      SecureShortAuthenticationString.unpackIndices(trailingBits),
      SecureShortAuthenticationString.unpackIndices(consumedBit)
    )
  }

  func testDerivationLabelIsTheVersionedSASDomain() {
    let expected = CanonicalStatementEncoder(domain: .shortAuthenticationString)
    XCTAssertEqual(SecureShortAuthenticationString.derivationLabel, expected.encodedBytes)
    XCTAssertEqual(expected.encodedBytes.first, CanonicalStatementVersion.current)
  }

  func testWrongTranscriptHashLengthFailsClosed() {
    XCTAssertThrowsError(
      try SecureShortAuthenticationString.derive(fromTranscriptHash: Data(count: 16)))
    XCTAssertThrowsError(
      try SecureShortAuthenticationString.derive(fromTranscriptHash: Data(count: 33)))
  }
}
