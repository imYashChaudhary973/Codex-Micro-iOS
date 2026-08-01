import CompanionProtocol
import Foundation
import XCTest

/// Shared canonical values and golden JSON fixtures for the Step 2.2 secure
/// wire contracts. Fixtures are byte-exact against the canonical encoder
/// (sorted keys, unescaped slashes, base64 data).
enum SecureFixtures {
  static let pairingSessionID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
  static let hostID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
  static let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  static let sessionID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
  static let subscriptionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
  static let commandID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!

  static func encoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return encoder
  }

  static func selection() throws -> SecureProtocolSelection {
    try SecureProtocolSelection(major: 1, minor: 1, features: Set(SecureProtocolFeature.allCases))
  }

  static func journalEpoch() throws -> JournalEpoch {
    try JournalEpoch(rawBytes: Data(repeating: 0x77, count: 16))
  }

  static func cursor() throws -> ReplayCursorEnvelope {
    ReplayCursorEnvelope(
      deviceID: deviceID,
      grantRevision: 7,
      authorizedViewEpoch: 3,
      journalEpoch: try journalEpoch(),
      sequence: 42
    )
  }

  static func authority(
    grantRevision: UInt64 = 7,
    authorizedViewEpoch: UInt64 = 3,
    journalEpochByte: UInt8 = 0x77,
    latestSequence: UInt64 = 50,
    oldestReplayableSequence: UInt64 = 10,
    deviceID: UUID = SecureFixtures.deviceID
  ) throws -> ReplayCursorAuthority {
    try ReplayCursorAuthority(
      deviceID: deviceID,
      grantRevision: grantRevision,
      authorizedViewEpoch: authorizedViewEpoch,
      journalEpoch: JournalEpoch(rawBytes: Data(repeating: journalEpochByte, count: 16)),
      latestSequence: latestSequence,
      oldestReplayableSequence: oldestReplayableSequence
    )
  }

  static let selectionJSON =
    #"{"features":["observe-sync-v1","thread-read-cursor-v1","turn-interrupt-v1"],"major":1,"minor":1}"#

  static let cursorJSON =
    #"{"authorizedViewEpoch":3,"deviceID":"33333333-3333-3333-3333-333333333333","grantRevision":7,"journalEpoch":"d3d3d3d3d3d3d3d3d3d3dw==","sequence":42}"#

  static let problemJSON = #"{"reason":"invalidCursor"}"#

  static let closeJSON = #"{"reason":"sessionReplaced"}"#
}

final class SecureWireGoldenFixtureTests: XCTestCase {
  private func assertGolden<Message: Codable & Equatable>(
    _ value: Message,
    matches fixture: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    let encoded = try SecureFixtures.encoder().encode(value)
    XCTAssertEqual(String(decoding: encoded, as: UTF8.self), fixture, file: file, line: line)

    let decoded = try JSONDecoder().decode(Message.self, from: Data(fixture.utf8))
    XCTAssertEqual(decoded, value, file: file, line: line)

    let reencoded = try SecureFixtures.encoder().encode(decoded)
    XCTAssertEqual(reencoded, Data(fixture.utf8), file: file, line: line)
  }

  func testProtocolSelectionGoldenFixture() throws {
    try assertGolden(SecureFixtures.selection(), matches: SecureFixtures.selectionJSON)
  }

  func testReplayCursorGoldenFixture() throws {
    try assertGolden(SecureFixtures.cursor(), matches: SecureFixtures.cursorJSON)
  }

  func testProblemNoticeGoldenFixture() throws {
    try assertGolden(
      SecureProblemNotice(reason: .invalidCursor),
      matches: SecureFixtures.problemJSON
    )
  }

  func testCloseNoticeGoldenFixture() throws {
    try assertGolden(
      SecureCloseNotice(reason: .sessionReplaced),
      matches: SecureFixtures.closeJSON
    )
  }
}
