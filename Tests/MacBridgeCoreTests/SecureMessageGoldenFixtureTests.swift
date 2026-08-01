import CompanionProtocol
import Foundation
import XCTest

/// Golden JSON fixtures for the Step 2.2 secure-session message schemas.
/// Extends the shared `SecureFixtures` canonical values defined alongside the
/// foundation contracts; fixtures remain byte-exact against the canonical
/// encoder (sorted keys, unescaped slashes, base64 data).
extension SecureFixtures {
  static let pairingRequestJSON =
    #"{"bootstrapSecret":"ERERERERERERERERERERERERERERERERERERERERERE=","deviceNonce":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=","devicePublicKey":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=","endpointOrigin":"wss://192.168.1.20:8443","mode":"direct-lan","pairingSessionID":"11111111-1111-1111-1111-111111111111","selection":{"features":["observe-sync-v1","thread-read-cursor-v1","turn-interrupt-v1"],"major":1,"minor":1}}"#

  static let pairingResponseJSON =
    #"{"hostID":"22222222-2222-2222-2222-222222222222","hostNonce":"REREREREREREREREREREREREREREREREREREREREREQ=","hostPublicKey":"VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=","pairingSessionID":"11111111-1111-1111-1111-111111111111","selection":{"features":["observe-sync-v1","thread-read-cursor-v1","turn-interrupt-v1"],"major":1,"minor":1},"transcriptSignature":"ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg=="}"#

  static let authRequestJSON =
    #"{"deviceEphemeralPublicKey":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=","deviceID":"33333333-3333-3333-3333-333333333333","deviceNonce":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=","selection":{"features":["observe-sync-v1","thread-read-cursor-v1","turn-interrupt-v1"],"major":1,"minor":1},"transcriptSignature":"ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg=="}"#

  static let authResponseJSON =
    #"{"authorizedViewEpoch":3,"grantRevision":7,"hostEphemeralPublicKey":"VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=","hostGeneration":1,"hostNonce":"REREREREREREREREREREREREREREREREREREREREREQ=","selection":{"features":["observe-sync-v1","thread-read-cursor-v1","turn-interrupt-v1"],"major":1,"minor":1},"sessionID":"44444444-4444-4444-4444-444444444444","transcriptSignature":"ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg=="}"#

  static let subscribeJSON =
    #"{"resumeCursor":{"authorizedViewEpoch":3,"deviceID":"33333333-3333-3333-3333-333333333333","grantRevision":7,"journalEpoch":"d3d3d3d3d3d3d3d3d3d3dw==","sequence":42},"subscriptionID":"55555555-5555-5555-5555-555555555555"}"#

  static let subscribeFreshJSON =
    #"{"subscriptionID":"55555555-5555-5555-5555-555555555555"}"#

  static let acknowledgementJSON =
    #"{"cursor":{"authorizedViewEpoch":3,"deviceID":"33333333-3333-3333-3333-333333333333","grantRevision":7,"journalEpoch":"d3d3d3d3d3d3d3d3d3d3dw==","sequence":42},"subscriptionID":"55555555-5555-5555-5555-555555555555"}"#

  static let deliveryJSON =
    #"{"cursor":{"authorizedViewEpoch":3,"deviceID":"33333333-3333-3333-3333-333333333333","grantRevision":7,"journalEpoch":"d3d3d3d3d3d3d3d3d3d3dw==","sequence":42},"kind":"event","payload":"iIiIiIiI","subscriptionID":"55555555-5555-5555-5555-555555555555"}"#

  static let commandResultCompletedJSON =
    #"{"commandID":"66666666-6666-6666-6666-666666666666","outcome":"completed"}"#

  static let commandResultDeniedJSON =
    #"{"commandID":"66666666-6666-6666-6666-666666666666","denialReason":"projectNotAllowed","outcome":"denied"}"#
}

final class SecureMessageGoldenFixtureTests: XCTestCase {
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

  func testPairingRequestGoldenFixture() throws {
    let message = try SecurePairingRequest(
      pairingSessionID: SecureFixtures.pairingSessionID,
      mode: .directLAN,
      endpointOrigin: "wss://192.168.1.20:8443",
      bootstrapSecret: Data(repeating: 0x11, count: 32),
      deviceNonce: Data(repeating: 0x22, count: 32),
      devicePublicKey: Data(repeating: 0x33, count: 65),
      selection: SecureFixtures.selection()
    )
    try assertGolden(message, matches: SecureFixtures.pairingRequestJSON)
  }

  func testPairingResponseGoldenFixture() throws {
    let message = try SecurePairingResponse(
      pairingSessionID: SecureFixtures.pairingSessionID,
      hostID: SecureFixtures.hostID,
      hostNonce: Data(repeating: 0x44, count: 32),
      hostPublicKey: Data(repeating: 0x55, count: 65),
      selection: SecureFixtures.selection(),
      transcriptSignature: Data(repeating: 0x66, count: 64)
    )
    try assertGolden(message, matches: SecureFixtures.pairingResponseJSON)
  }

  func testSessionAuthRequestGoldenFixture() throws {
    let message = try SecureSessionAuthRequest(
      deviceID: SecureFixtures.deviceID,
      selection: SecureFixtures.selection(),
      deviceEphemeralPublicKey: Data(repeating: 0x33, count: 65),
      deviceNonce: Data(repeating: 0x22, count: 32),
      transcriptSignature: Data(repeating: 0x66, count: 64)
    )
    try assertGolden(message, matches: SecureFixtures.authRequestJSON)
  }

  func testSessionAuthResponseGoldenFixture() throws {
    let message = try SecureSessionAuthResponse(
      sessionID: SecureFixtures.sessionID,
      selection: SecureFixtures.selection(),
      hostEphemeralPublicKey: Data(repeating: 0x55, count: 65),
      hostNonce: Data(repeating: 0x44, count: 32),
      grantRevision: 7,
      authorizedViewEpoch: 3,
      hostGeneration: 1,
      transcriptSignature: Data(repeating: 0x66, count: 64)
    )
    try assertGolden(message, matches: SecureFixtures.authResponseJSON)
  }

  func testObservationSubscribeGoldenFixture() throws {
    let message = SecureObservationSubscribe(
      subscriptionID: SecureFixtures.subscriptionID,
      resumeCursor: try SecureFixtures.cursor()
    )
    try assertGolden(message, matches: SecureFixtures.subscribeJSON)
  }

  func testObservationSubscribeFreshGoldenFixture() throws {
    let message = SecureObservationSubscribe(
      subscriptionID: SecureFixtures.subscriptionID,
      resumeCursor: nil
    )
    try assertGolden(message, matches: SecureFixtures.subscribeFreshJSON)
  }

  func testObservationAcknowledgementGoldenFixture() throws {
    let message = SecureObservationAcknowledgement(
      subscriptionID: SecureFixtures.subscriptionID,
      cursor: try SecureFixtures.cursor()
    )
    try assertGolden(message, matches: SecureFixtures.acknowledgementJSON)
  }

  func testObservationDeliveryGoldenFixture() throws {
    let message = try SecureObservationDelivery(
      subscriptionID: SecureFixtures.subscriptionID,
      kind: .event,
      cursor: SecureFixtures.cursor(),
      payload: Data(repeating: 0x88, count: 6)
    )
    try assertGolden(message, matches: SecureFixtures.deliveryJSON)
  }

  func testCommandResultCompletedGoldenFixture() throws {
    let message = try SecureCommandResult(
      commandID: SecureFixtures.commandID,
      outcome: .completed,
      denialReason: nil
    )
    try assertGolden(message, matches: SecureFixtures.commandResultCompletedJSON)
  }

  func testCommandResultDeniedGoldenFixture() throws {
    let message = try SecureCommandResult(
      commandID: SecureFixtures.commandID,
      outcome: .denied,
      denialReason: .projectNotAllowed
    )
    try assertGolden(message, matches: SecureFixtures.commandResultDeniedJSON)
  }
}
