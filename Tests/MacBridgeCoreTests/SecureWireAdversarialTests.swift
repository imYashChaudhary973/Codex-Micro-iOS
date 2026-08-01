import CompanionProtocol
import Foundation
import XCTest

final class SecureWireAdversarialTests: XCTestCase {
  private func assertRejects<Message: Decodable>(
    _ type: Message.Type,
    _ json: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertThrowsError(
      try JSONDecoder().decode(type, from: Data(json.utf8)),
      "Expected strict decoding to fail closed.",
      file: file,
      line: line
    )
  }

  private func mutated(_ json: String, _ target: String, _ replacement: String) -> String {
    XCTAssertTrue(json.contains(target), "Fixture mutation target missing: \(target)")
    return json.replacingOccurrences(of: target, with: replacement)
  }

  // MARK: - Exact minor/feature negotiation

  func testNegotiationAcceptsOnlyTheExactSupportedTuple() throws {
    let proposal = try SecureFixtures.selection()
    XCTAssertEqual(try SecureProtocolNegotiation.accept(proposal), proposal)
  }

  func testNegotiationRejectsFutureAndPastMinors() throws {
    let future = try SecureProtocolSelection(major: 1, minor: 2, features: [.observeSync])
    XCTAssertThrowsError(try SecureProtocolNegotiation.accept(future)) { error in
      XCTAssertEqual(error as? SecureProtocolNegotiationError, .unsupportedMinor)
    }
    let past = try SecureProtocolSelection(major: 1, minor: 0, features: [.observeSync])
    XCTAssertThrowsError(try SecureProtocolNegotiation.accept(past)) { error in
      XCTAssertEqual(error as? SecureProtocolNegotiationError, .unsupportedMinor)
    }
  }

  func testNegotiationRejectsWrongMajor() throws {
    let downgrade = try SecureProtocolSelection(major: 0, minor: 1, features: [.observeSync])
    XCTAssertThrowsError(try SecureProtocolNegotiation.accept(downgrade)) { error in
      XCTAssertEqual(error as? SecureProtocolNegotiationError, .unsupportedMajor)
    }
    let upgrade = try SecureProtocolSelection(major: 2, minor: 1, features: [.observeSync])
    XCTAssertThrowsError(try SecureProtocolNegotiation.accept(upgrade)) { error in
      XCTAssertEqual(error as? SecureProtocolNegotiationError, .unsupportedMajor)
    }
  }

  func testNegotiationRejectsFeatureOutsideSupportedSet() throws {
    let proposal = try SecureProtocolSelection(
      major: 1, minor: 1, features: [.observeSync, .turnInterrupt])
    XCTAssertThrowsError(
      try SecureProtocolNegotiation.accept(proposal, supportedFeatures: [.observeSync])
    ) { error in
      XCTAssertEqual(error as? SecureProtocolNegotiationError, .unsupportedFeature)
    }
  }

  func testUnknownFeatureIdentifierFailsClosed() {
    assertRejects(
      SecureProtocolSelection.self,
      mutated(SecureFixtures.selectionJSON, "observe-sync-v1", "approval-v1")
    )
  }

  func testDuplicateFeaturesFailClosed() {
    assertRejects(
      SecureProtocolSelection.self,
      mutated(SecureFixtures.selectionJSON, "thread-read-cursor-v1", "observe-sync-v1")
    )
  }

  func testEmptyFeatureSetFailsClosed() {
    assertRejects(
      SecureProtocolSelection.self,
      #"{"features":[],"major":1,"minor":1}"#
    )
    XCTAssertThrowsError(try SecureProtocolSelection(major: 1, minor: 1, features: []))
  }

  func testPhase2DefinesNoApprovalFeature() {
    XCTAssertEqual(SecureProtocolFeature.allCases.count, 3)
    for feature in SecureProtocolFeature.allCases {
      XCTAssertFalse(feature.rawValue.lowercased().contains("approv"))
    }
    XCTAssertEqual(
      SecureProtocolNegotiation.supportedFeatures, Set(SecureProtocolFeature.allCases))
  }

  func testSelectionUnknownFieldAndWrongTypeFailClosed() {
    assertRejects(
      SecureProtocolSelection.self,
      mutated(SecureFixtures.selectionJSON, #""major":1"#, #""major":1,"patch":0"#)
    )
    assertRejects(
      SecureProtocolSelection.self,
      mutated(SecureFixtures.selectionJSON, #""major":1"#, #""major":"1""#)
    )
  }

  // MARK: - Problem and close notices

  func testProblemNoticeRejectsUnknownReasonAndFreeFormPayload() {
    assertRejects(
      SecureProblemNotice.self,
      mutated(SecureFixtures.problemJSON, "invalidCursor", "stackTrace")
    )
    assertRejects(
      SecureProblemNotice.self,
      mutated(
        SecureFixtures.problemJSON,
        #""reason":"invalidCursor""#,
        #""reason":"invalidCursor","detail":"grant 7 for device X missing""#
      )
    )
  }

  func testCloseNoticeRejectsUnknownReasonAndFreeFormPayload() {
    assertRejects(
      SecureCloseNotice.self,
      mutated(SecureFixtures.closeJSON, "sessionReplaced", "debugDump")
    )
    assertRejects(
      SecureCloseNotice.self,
      mutated(
        SecureFixtures.closeJSON,
        #""reason":"sessionReplaced""#,
        #""message":"revoked by admin","reason":"sessionReplaced""#
      )
    )
  }

  // MARK: - Replay cursor schema

  func testCursorUnknownFieldFailsClosed() {
    assertRejects(
      ReplayCursorEnvelope.self,
      mutated(SecureFixtures.cursorJSON, #""sequence":42"#, #""sequence":42,"admin":true"#)
    )
  }

  func testCursorWrongJournalEpochLengthFailsClosed() {
    for count in [0, 15, 17] {
      let epoch = Data(repeating: 0x77, count: count).base64EncodedString()
      assertRejects(
        ReplayCursorEnvelope.self,
        mutated(SecureFixtures.cursorJSON, "d3d3d3d3d3d3d3d3d3d3dw==", epoch)
      )
    }
  }

  func testCursorMalformedSequenceFailsClosed() {
    assertRejects(
      ReplayCursorEnvelope.self,
      mutated(SecureFixtures.cursorJSON, #""sequence":42"#, #""sequence":-1"#)
    )
    assertRejects(
      ReplayCursorEnvelope.self,
      mutated(SecureFixtures.cursorJSON, #""sequence":42"#, #""sequence":"42""#)
    )
    assertRejects(
      ReplayCursorEnvelope.self,
      mutated(
        SecureFixtures.cursorJSON,
        #""deviceID":"33333333-3333-3333-3333-333333333333""#,
        #""deviceID":"not-a-uuid""#
      )
    )
  }

  func testJournalEpochInitEnforcesExactLength() {
    XCTAssertThrowsError(try JournalEpoch(rawBytes: Data(repeating: 0x77, count: 15)))
    XCTAssertThrowsError(try JournalEpoch(rawBytes: Data(repeating: 0x77, count: 17)))
    XCTAssertThrowsError(try JournalEpoch(rawBytes: Data()))
    XCTAssertNoThrow(try JournalEpoch(rawBytes: Data(repeating: 0x77, count: 16)))
  }

  // MARK: - ADR constants

  func testTransportLimitsMatchTransportADR() {
    XCTAssertEqual(SecureTransportLimits.maxFrameBytes, 16_384)
    XCTAssertEqual(SecureTransportLimits.maxMessageBytes, 65_536)
    XCTAssertEqual(SecureTransportLimits.maxFragmentsPerMessage, 8)
    XCTAssertEqual(SecureTransportLimits.maxHeaderFieldCount, 16)
    XCTAssertEqual(SecureTransportLimits.maxHeaderTotalBytes, 8_192)
    XCTAssertEqual(SecureTransportLimits.maxHeaderFieldBytes, 4_096)
    XCTAssertEqual(SecureTransportLimits.upgradeDeadlineSeconds, 10)
    XCTAssertEqual(SecureTransportLimits.authenticationDeadlineSeconds, 20)
    XCTAssertEqual(SecureTransportLimits.maxConcurrentConnections, 16)
    XCTAssertEqual(SecureTransportLimits.maxUnauthenticatedConnections, 4)
    XCTAssertEqual(SecureTransportLimits.maxNewConnectionsPerSourcePerMinute, 6)
    XCTAssertEqual(SecureTransportLimits.maxPairingAttemptsPerSourcePerMinute, 3)
    XCTAssertEqual(SecureTransportLimits.maxInboundMessagesPerSecond, 32)
    XCTAssertEqual(SecureTransportLimits.maxInboundBytesPerSecond, 1_048_576)
    XCTAssertEqual(SecureTransportLimits.maxOutboundQueueFrames, 64)
    XCTAssertEqual(SecureTransportLimits.maxOutboundQueueBytes, 262_144)
    XCTAssertEqual(SecureTransportLimits.maxNonWritableSeconds, 10)
    XCTAssertEqual(SecureTransportLimits.pingCadenceSeconds, 30)
    XCTAssertEqual(SecureTransportLimits.pongDeadlineSeconds, 10)
    XCTAssertEqual(SecureTransportLimits.idleExpirySeconds, 120)
    XCTAssertEqual(SecureTransportLimits.nonceByteCount, 32)
    XCTAssertEqual(SecureTransportLimits.bootstrapSecretByteCount, 32)
    XCTAssertEqual(SecureTransportLimits.signatureByteCount, 64)
    XCTAssertEqual(SecureTransportLimits.journalEpochByteCount, 16)
  }
}
