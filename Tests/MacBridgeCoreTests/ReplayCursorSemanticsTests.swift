import CompanionProtocol
import Foundation
import XCTest

final class ReplayCursorSemanticsTests: XCTestCase {
  private func cursor(
    deviceID: UUID = SecureFixtures.deviceID,
    grantRevision: UInt64 = 7,
    authorizedViewEpoch: UInt64 = 3,
    journalEpochByte: UInt8 = 0x77,
    sequence: UInt64 = 42
  ) throws -> ReplayCursorEnvelope {
    ReplayCursorEnvelope(
      deviceID: deviceID,
      grantRevision: grantRevision,
      authorizedViewEpoch: authorizedViewEpoch,
      journalEpoch: try JournalEpoch(rawBytes: Data(repeating: journalEpochByte, count: 16)),
      sequence: sequence
    )
  }

  func testMatchingCurrentValuesMayReplay() throws {
    let decision = try cursor().evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .replay(afterSequence: 42))
  }

  func testCursorAtLatestSequenceReplaysNothingNewButIsValid() throws {
    let decision = try cursor(sequence: 50).evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .replay(afterSequence: 50))
  }

  func testOlderGrantRevisionForcesSnapshot() throws {
    let decision = try cursor(grantRevision: 6).evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .snapshot(.staleGrantRevision))
  }

  func testOlderAuthorizedViewEpochForcesSnapshot() throws {
    let decision = try cursor(authorizedViewEpoch: 2).evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .snapshot(.staleAuthorizedViewEpoch))
  }

  func testForeignJournalEpochForcesSnapshot() throws {
    let decision = try cursor(journalEpochByte: 0x78)
      .evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .snapshot(.foreignJournalEpoch))
  }

  func testForeignJournalEpochWithHugeSequenceStillForcesSnapshotNotComparison() throws {
    let decision = try cursor(journalEpochByte: 0x78, sequence: 9_000_000)
      .evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .snapshot(.foreignJournalEpoch))
  }

  func testRetentionStaleCursorForcesSnapshot() throws {
    let decision = try cursor(sequence: 9)
      .evaluate(against: SecureFixtures.authority(oldestReplayableSequence: 10))
    XCTAssertEqual(decision, .snapshot(.retentionExpired))
  }

  func testMismatchedDeviceFailsClosed() throws {
    let decision = try cursor(deviceID: SecureFixtures.hostID)
      .evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .reject(.deviceMismatch))
  }

  func testMismatchedDeviceFailsClosedEvenWhenOtherwiseStale() throws {
    let decision = try cursor(deviceID: SecureFixtures.hostID, grantRevision: 1)
      .evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .reject(.deviceMismatch))
  }

  func testAheadSequenceFailsClosed() throws {
    let decision = try cursor(sequence: 51).evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .reject(.sequenceAhead))
  }

  func testGrantRevisionAheadOfAuthorityIsRollbackAndFailsClosed() throws {
    let decision = try cursor(grantRevision: 8).evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .reject(.grantRevisionAhead))
  }

  func testAuthorizedViewEpochAheadOfAuthorityFailsClosed() throws {
    let decision = try cursor(authorizedViewEpoch: 4)
      .evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .reject(.authorizedViewEpochAhead))
  }

  func testSequenceCounterOverflowFailsClosed() throws {
    let decision = try cursor(sequence: UInt64.max)
      .evaluate(against: SecureFixtures.authority())
    XCTAssertEqual(decision, .reject(.counterOverflow))
  }

  func testGrantRevisionOverflowFailsClosedInsteadOfWrapping() throws {
    let decision = try cursor(grantRevision: UInt64.max)
      .evaluate(against: SecureFixtures.authority(grantRevision: UInt64.max))
    XCTAssertEqual(decision, .reject(.counterOverflow))
  }

  func testAuthorityLatestSequenceOverflowFailsClosed() throws {
    let decision = try cursor()
      .evaluate(against: SecureFixtures.authority(latestSequence: UInt64.max))
    XCTAssertEqual(decision, .reject(.counterOverflow))
  }

  func testAuthorizedViewEpochOverflowFailsClosed() throws {
    let decision = try cursor(authorizedViewEpoch: UInt64.max)
      .evaluate(against: SecureFixtures.authority(authorizedViewEpoch: UInt64.max))
    XCTAssertEqual(decision, .reject(.counterOverflow))
  }

  func testAuthorityRejectsInvertedRetentionWindow() {
    XCTAssertThrowsError(
      try SecureFixtures.authority(latestSequence: 5, oldestReplayableSequence: 6)
    ) { error in
      XCTAssertEqual(
        error as? SecureWireValidationError,
        .invalidField(name: "oldestReplayableSequence")
      )
    }
  }
}
