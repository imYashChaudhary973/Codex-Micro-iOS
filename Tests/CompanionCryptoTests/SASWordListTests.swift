import CompanionProtocol
import Foundation
import XCTest

@testable import CompanionCrypto

/// The fixed versioned word list the verification phrase renders through.
///
/// Step 2.3 deferred it twice on the grounds that a transcribed
/// natural-language list is 2,048 chances for a silent typo, and one wrong
/// entry makes two honest devices disagree about an identical phrase.
/// Generating it removes that failure mode, and these tests are what make the
/// generation trustworthy.
final class SASWordListTests: XCTestCase {

  // MARK: - The SAS word list

  func testTheListHasExactlyOneWordPerIndex() {
    XCTAssertEqual(SecureSASWordList.count, 2048)
    XCTAssertEqual(SecureSASWordList.words.count, 2048)
    XCTAssertEqual(
      SecureSASWordList.count, Int(SecureShortAuthenticationString.indexUpperBound))
  }

  /// The whole reason the list is generated rather than transcribed: a
  /// duplicate would make two distinct phrases render identically.
  func testEveryWordIsDistinct() {
    XCTAssertEqual(Set(SecureSASWordList.words).count, SecureSASWordList.words.count)
  }

  func testTheAlphabetSizesMultiplyToTheListSize() {
    XCTAssertEqual(
      SecureSASWordList.onsets.count * SecureSASWordList.nuclei.count
        * SecureSASWordList.codas.count,
      2048
    )
    XCTAssertEqual(Set(SecureSASWordList.onsets).count, SecureSASWordList.onsets.count)
    XCTAssertEqual(Set(SecureSASWordList.nuclei).count, SecureSASWordList.nuclei.count)
    XCTAssertEqual(Set(SecureSASWordList.codas).count, SecureSASWordList.codas.count)
  }

  func testEveryIndexInRangeResolvesAndNothingElseDoes() {
    for index in 0..<SecureShortAuthenticationString.indexUpperBound {
      XCTAssertNotNil(SecureSASWordList.word(at: index), "\(index)")
    }
    XCTAssertNil(SecureSASWordList.word(at: SecureShortAuthenticationString.indexUpperBound))
    XCTAssertNil(SecureSASWordList.word(at: UInt16.max))
  }

  func testWordsAreLowercaseAsciiLettersOnly() {
    for word in SecureSASWordList.words {
      XCTAssertTrue(
        word.allSatisfy { $0.isASCII && $0.isLowercase && $0.isLetter }, word)
      XCTAssertGreaterThanOrEqual(word.count, 3)
      XCTAssertLessThanOrEqual(word.count, 5)
    }
  }

  func testTheListIsDeterministicAcrossBuilds() {
    // Index order is fixed by the nested generation order, so two endpoints
    // building the list independently agree.
    XCTAssertEqual(SecureSASWordList.words.first, "bab")
    XCTAssertEqual(SecureSASWordList.word(at: 0), "bab")
    XCTAssertEqual(SecureSASWordList.word(at: 1), "bad")
    XCTAssertEqual(SecureSASWordList.words.last, SecureSASWordList.word(at: 2047))
  }

  func testTheListIsVersioned() {
    XCTAssertEqual(SecureSASWordList.version, "codex-micro/sas-words/v1")
  }

  /// Both renderings carry the same 66 bits; neither is authoritative.
  func testTheWordPhraseAndTheDecimalGroupsAgree() throws {
    let sas = try sampleSAS()

    XCTAssertEqual(sas.displayWords.count, SecureShortAuthenticationString.indexCount)
    XCTAssertEqual(sas.displayGroups.count, SecureShortAuthenticationString.indexCount)
    for (offset, index) in sas.indices.enumerated() {
      XCTAssertEqual(sas.displayWords[offset], SecureSASWordList.word(at: index))
    }
    XCTAssertEqual(
      sas.displayPhrase, sas.displayWords.joined(separator: " "))
  }

  func testADifferentPhraseRendersDifferentWords() throws {
    let first = try sampleSAS()
    let second = try SecureShortAuthenticationString(
      indices: [1, 2, 3, 4, 5, 6])

    XCTAssertNotEqual(first.displayWords, second.displayWords)
  }

  private func sampleSAS() throws -> SecureShortAuthenticationString {
    try SecureShortAuthenticationString(indices: [0, 1, 2047, 1024, 512, 7])
  }
}
