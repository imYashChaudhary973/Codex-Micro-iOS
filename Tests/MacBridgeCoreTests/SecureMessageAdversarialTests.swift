import CompanionProtocol
import Foundation
import XCTest

/// Adversarial strict-decoding coverage for the Step 2.2 secure-session
/// message schemas. Complements the foundation adversarial suite, which owns
/// negotiation, notice, cursor-schema, and constants coverage.
final class SecureMessageAdversarialTests: XCTestCase {
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

  // MARK: - Pairing messages

  func testPairingRequestUnknownFieldFailsClosed() {
    assertRejects(
      SecurePairingRequest.self,
      mutated(
        SecureFixtures.pairingRequestJSON,
        #""mode":"direct-lan""#,
        #""mode":"direct-lan","hostName":"attacker""#
      )
    )
  }

  func testPairingRequestUnknownModeFailsClosed() {
    assertRejects(
      SecurePairingRequest.self,
      mutated(SecureFixtures.pairingRequestJSON, #""mode":"direct-lan""#, #""mode":"relay""#)
    )
  }

  func testPairingRequestWrongSecretLengthFailsClosed() {
    let short = Data(repeating: 0x11, count: 31).base64EncodedString()
    assertRejects(
      SecurePairingRequest.self,
      mutated(
        SecureFixtures.pairingRequestJSON,
        "ERERERERERERERERERERERERERERERERERERERERERE=",
        short
      )
    )
    XCTAssertThrowsError(
      try SecurePairingRequest(
        pairingSessionID: SecureFixtures.pairingSessionID,
        mode: .directLAN,
        endpointOrigin: "wss://192.168.1.20:8443",
        bootstrapSecret: Data(repeating: 0x11, count: 33),
        deviceNonce: Data(repeating: 0x22, count: 32),
        devicePublicKey: Data(repeating: 0x33, count: 65),
        selection: SecureFixtures.selection()
      )
    ) { error in
      XCTAssertEqual(
        error as? SecureWireValidationError, .invalidField(name: "bootstrapSecret"))
    }
  }

  func testPairingRequestEndpointOriginBoundsFailClosed() {
    let empty = mutated(
      SecureFixtures.pairingRequestJSON, "wss://192.168.1.20:8443", "")
    assertRejects(SecurePairingRequest.self, empty)

    let oversized = mutated(
      SecureFixtures.pairingRequestJSON,
      "wss://192.168.1.20:8443",
      String(repeating: "a", count: 129)
    )
    assertRejects(SecurePairingRequest.self, oversized)

    let control = mutated(
      SecureFixtures.pairingRequestJSON,
      "wss://192.168.1.20:8443",
      #"wss://192.168.1.20:8443\n"#
    )
    assertRejects(SecurePairingRequest.self, control)
  }

  func testPairingResponseWrongSignatureLengthFailsClosed() {
    let short = Data(repeating: 0x66, count: 63).base64EncodedString()
    assertRejects(
      SecurePairingResponse.self,
      mutated(
        SecureFixtures.pairingResponseJSON,
        "ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg==",
        short
      )
    )
  }

  func testPairingResponseUnknownFieldFailsClosed() {
    assertRejects(
      SecurePairingResponse.self,
      mutated(
        SecureFixtures.pairingResponseJSON,
        #""hostID":"#,
        #""hostDisplayName":"Attacker Mac","hostID":"#
      )
    )
  }

  // MARK: - Session authentication messages

  func testAuthRequestUnknownFieldFailsClosed() {
    assertRejects(
      SecureSessionAuthRequest.self,
      mutated(
        SecureFixtures.authRequestJSON,
        #""deviceID":"#,
        #""approvalToken":"granted","deviceID":"#
      )
    )
  }

  func testAuthRequestWrongPublicKeyLengthFailsClosed() {
    let wrong = Data(repeating: 0x33, count: 64).base64EncodedString()
    assertRejects(
      SecureSessionAuthRequest.self,
      mutated(
        SecureFixtures.authRequestJSON,
        "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
        wrong
      )
    )
  }

  func testAuthRequestWrongSignatureTypeFailsClosed() {
    assertRejects(
      SecureSessionAuthRequest.self,
      mutated(
        SecureFixtures.authRequestJSON,
        #""transcriptSignature":"ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg==""#,
        #""transcriptSignature":12345"#
      )
    )
  }

  func testAuthResponseNegativeCounterFailsClosed() {
    assertRejects(
      SecureSessionAuthResponse.self,
      mutated(SecureFixtures.authResponseJSON, #""grantRevision":7"#, #""grantRevision":-7"#)
    )
    assertRejects(
      SecureSessionAuthResponse.self,
      mutated(SecureFixtures.authResponseJSON, #""hostGeneration":1"#, #""hostGeneration":1.5"#)
    )
  }

  func testAuthResponseUnknownFieldFailsClosed() {
    assertRejects(
      SecureSessionAuthResponse.self,
      mutated(
        SecureFixtures.authResponseJSON,
        #""sessionID":"#,
        #""projectNames":["secret-project"],"sessionID":"#
      )
    )
  }

  // MARK: - Observation messages

  func testSubscribeUnknownFieldFailsClosed() {
    assertRejects(
      SecureObservationSubscribe.self,
      mutated(
        SecureFixtures.subscribeFreshJSON,
        #""subscriptionID":"#,
        #""allProjects":true,"subscriptionID":"#
      )
    )
  }

  func testSubscribeNestedCursorUnknownFieldFailsClosed() {
    assertRejects(
      SecureObservationSubscribe.self,
      mutated(
        SecureFixtures.subscribeJSON,
        #""sequence":42"#,
        #""sequence":42,"skipFiltering":true"#
      )
    )
  }

  func testAcknowledgementMissingCursorFailsClosed() {
    assertRejects(
      SecureObservationAcknowledgement.self,
      SecureFixtures.subscribeFreshJSON
    )
  }

  func testDeliveryUnknownKindFailsClosed() {
    assertRejects(
      SecureObservationDelivery.self,
      mutated(SecureFixtures.deliveryJSON, #""kind":"event""#, #""kind":"rawDiff""#)
    )
  }

  func testDeliveryPayloadBoundsFailClosed() throws {
    assertRejects(
      SecureObservationDelivery.self,
      mutated(SecureFixtures.deliveryJSON, #""payload":"iIiIiIiI""#, #""payload":"""#)
    )
    let oversized = Data(
      repeating: 0x88, count: SecureTransportLimits.maxObservationPayloadBytes + 1)
    assertRejects(
      SecureObservationDelivery.self,
      mutated(
        SecureFixtures.deliveryJSON,
        #""payload":"iIiIiIiI""#,
        #""payload":"\#(oversized.base64EncodedString())""#
      )
    )
    XCTAssertThrowsError(
      try SecureObservationDelivery(
        subscriptionID: SecureFixtures.subscriptionID,
        kind: .snapshot,
        cursor: SecureFixtures.cursor(),
        payload: Data()
      )
    ) { error in
      XCTAssertEqual(error as? SecureWireValidationError, .invalidField(name: "payload"))
    }
  }

  // MARK: - Command results

  func testCommandResultDenialConsistencyFailsClosed() {
    assertRejects(
      SecureCommandResult.self,
      mutated(
        SecureFixtures.commandResultDeniedJSON,
        #""denialReason":"projectNotAllowed","#,
        ""
      )
    )
    assertRejects(
      SecureCommandResult.self,
      mutated(
        SecureFixtures.commandResultCompletedJSON,
        #""outcome":"completed""#,
        #""denialReason":"staleCommand","outcome":"completed""#
      )
    )
    XCTAssertThrowsError(
      try SecureCommandResult(
        commandID: SecureFixtures.commandID, outcome: .denied, denialReason: nil))
  }

  func testCommandResultUnknownOutcomeFailsClosed() {
    assertRejects(
      SecureCommandResult.self,
      mutated(
        SecureFixtures.commandResultCompletedJSON,
        #""outcome":"completed""#,
        #""outcome":"succeeded""#
      )
    )
  }
}
