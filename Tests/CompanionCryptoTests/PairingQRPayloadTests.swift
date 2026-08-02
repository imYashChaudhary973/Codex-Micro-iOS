import CompanionProtocol
import Foundation
import XCTest

@testable import CompanionCrypto

/// The QR payload is an exact ADR §12 allowlist with an unambiguous canonical
/// encoding: byte-exact round trips, and every non-canonical form fails.
final class PairingQRPayloadTests: XCTestCase {
  private func assertRejects(
    _ encoding: Data,
    _ message: String,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertThrowsError(
      try PairingQRPayload(canonicalEncoding: encoding), message, file: file, line: line)
  }

  // MARK: - Canonical encoding

  func testGoldenCanonicalEncodingRoundTrip() throws {
    let payload = try PairingFixtures.qrPayload()
    let encoded = payload.canonicalEncoding()
    XCTAssertEqual(encoded.hexFixture, GoldenVectors.pairingQRPayloadHex)

    let decoded = try PairingQRPayload(canonicalEncoding: encoded)
    XCTAssertEqual(decoded, payload)
    XCTAssertEqual(decoded.canonicalEncoding(), encoded)
  }

  func testEncodingLeadsWithVersionAndItsOwnDomain() throws {
    let encoded = try PairingFixtures.qrPayload().canonicalEncoding()
    let domain = Data(CanonicalStatementDomain.pairingQRPayload.rawValue.utf8)
    XCTAssertEqual(encoded[0], CanonicalStatementVersion.current)
    XCTAssertEqual(PairingQRPayload.version, CanonicalStatementVersion.current)
    XCTAssertEqual(encoded[1], 0)
    XCTAssertEqual(Int(encoded[2]), domain.count)
    XCTAssertEqual(encoded.subdata(in: 3..<(3 + domain.count)), domain)
  }

  func testPayloadCarriesExactlyTheAllowlistedFields() throws {
    let payload = try PairingFixtures.qrPayload()
    let fields = Mirror(reflecting: payload).children.compactMap(\.label)
    XCTAssertEqual(
      PairingQRPayload.allowlistedFields,
      [
        "selection",
        "hostID",
        "endpointOrigin",
        "hostIdentityFingerprint",
        "tlsSPKIFingerprint",
        "pairingSessionID",
        "bootstrapSecret",
        "expiresAtEpochSeconds",
      ]
    )
    XCTAssertEqual(fields, PairingQRPayload.allowlistedFields)
    // ADR §12 excludes host, device, user, and project descriptors outright.
    for excluded in ["hostName", "displayName", "name", "deviceID", "project", "user"] {
      XCTAssertFalse(fields.contains(excluded), excluded)
    }
    // The byte-exact golden vector above is the authoritative guard against an
    // added field; this is the version byte, the domain, and the eight
    // allowlisted values, nothing else.
    XCTAssertEqual(payload.canonicalEncoding().count, 264)
  }

  func testPayloadDescriptionAndReflectionRedactTheSecret() throws {
    let payload = try PairingFixtures.qrPayload()
    let secretFragment = PairingFixtures.bootstrapSecret.hexFixture

    for rendered in [payload.description, payload.debugDescription, "\(payload)"] {
      XCTAssertEqual(rendered, "PairingQRPayload(redacted)")
    }

    var dumped = ""
    dump(payload, to: &dumped)
    XCTAssertFalse(dumped.contains(secretFragment))
    XCTAssertTrue(dumped.contains(PairingQRPayload.redactedSecretMarker))

    let secretChild = Mirror(reflecting: payload).children.first { $0.label == "bootstrapSecret" }
    XCTAssertEqual(secretChild?.value as? String, PairingQRPayload.redactedSecretMarker)
  }

  func testSecretBearingTypesRedactTheirDescriptions() throws {
    let transcript = try CryptoFixtures.pairingTranscript()
    XCTAssertEqual("\(transcript)", "PairingTranscript(redacted)")
    XCTAssertEqual(String(reflecting: transcript), "PairingTranscript(redacted)")

    var dumped = ""
    dump(transcript, to: &dumped)
    XCTAssertFalse(dumped.contains(PairingFixtures.bootstrapSecret.hexFixture))
    XCTAssertFalse(dumped.contains("bootstrapSecret"))
  }

  // MARK: - Strict decoding

  func testWrongVersionAndForeignDomainFailClosed() throws {
    var wrongVersion = try PairingFixtures.qrPayload().canonicalEncoding()
    wrongVersion[0] = 2
    assertRejects(wrongVersion, "version")

    var encoder = CanonicalStatementEncoder(domain: .pairingTranscript)
    encoder.appendSelection(try CryptoFixtures.selection())
    assertRejects(encoder.encodedBytes, "domain")
  }

  func testTruncationAtEveryByteFailsClosed() throws {
    let encoded = try PairingFixtures.qrPayload().canonicalEncoding()
    for length in 0..<encoded.count {
      assertRejects(encoded.prefix(length), "truncated to \(length)")
    }
  }

  func testTrailingBytesFailClosed() throws {
    let encoded = try PairingFixtures.qrPayload().canonicalEncoding()
    assertRejects(encoded + Data([0x00]), "trailing")
  }

  func testPatchedFieldLengthsFailClosed() throws {
    let payload = try PairingFixtures.qrPayload()
    let encoded = payload.canonicalEncoding()
    // Every UInt16 length prefix in the encoding must match its declared
    // field width; flipping any of them fails closed.
    var patched = 0
    for index in 0..<(encoded.count - 1) where encoded[index] == 0x00 && encoded[index + 1] == 0x20
    {
      var mutation = encoded
      mutation[index + 1] = 0x1F
      assertRejects(mutation, "length prefix at \(index)")
      patched += 1
    }
    XCTAssertEqual(patched, 3, "expected the three 32-byte fields to be length-prefixed")
  }

  func testUnknownDuplicateAndMisorderedFeaturesFailClosed() throws {
    let payload = try PairingFixtures.qrPayload()

    func encoding(features: [String], count: UInt16? = nil) -> Data {
      var encoder = CanonicalStatementEncoder(domain: .pairingQRPayload)
      encoder.appendUInt16(payload.selection.major)
      encoder.appendUInt16(payload.selection.minor)
      encoder.appendUInt16(count ?? UInt16(features.count))
      for feature in features {
        encoder.appendText(feature)
      }
      encoder.appendUUID(payload.hostID)
      encoder.appendText(payload.endpointOrigin.normalized)
      encoder.appendVariableBytes(payload.hostIdentityFingerprint)
      encoder.appendVariableBytes(payload.tlsSPKIFingerprint)
      encoder.appendUUID(payload.pairingSessionID)
      encoder.appendVariableBytes(payload.bootstrapSecret)
      encoder.appendUInt64(payload.expiresAtEpochSeconds)
      return encoder.encodedBytes
    }

    assertRejects(encoding(features: ["observe-sync-v1", "approve-v1"]), "unknown feature")
    assertRejects(encoding(features: ["observe-sync-v1", "observe-sync-v1"]), "duplicate feature")
    assertRejects(
      encoding(features: ["turn-interrupt-v1", "observe-sync-v1"]), "misordered features")
    assertRejects(encoding(features: []), "empty feature set")
    assertRejects(
      encoding(features: ["observe-sync-v1"], count: 4), "feature count above the maximum")
  }

  func testNonNormalizedEndpointOriginInsideTheQRFailsClosed() throws {
    let payload = try PairingFixtures.qrPayload()

    func encoding(origin: String) -> Data {
      var encoder = CanonicalStatementEncoder(domain: .pairingQRPayload)
      encoder.appendSelection(payload.selection)
      encoder.appendUUID(payload.hostID)
      encoder.appendText(origin)
      encoder.appendVariableBytes(payload.hostIdentityFingerprint)
      encoder.appendVariableBytes(payload.tlsSPKIFingerprint)
      encoder.appendUUID(payload.pairingSessionID)
      encoder.appendVariableBytes(payload.bootstrapSecret)
      encoder.appendUInt64(payload.expiresAtEpochSeconds)
      return encoder.encodedBytes
    }

    assertRejects(encoding(origin: "WSS://192.168.4.20:8443"), "unnormalized scheme case")
    assertRejects(encoding(origin: "wss://192.168.4.20:443"), "unelided default port")
    assertRejects(encoding(origin: "wss://mac.local:8443"), "hostname origin")
    XCTAssertNoThrow(
      try PairingQRPayload(canonicalEncoding: encoding(origin: "wss://192.168.4.20:8443")))
  }

  func testConstructionRejectsWrongFieldLengths() throws {
    XCTAssertThrowsError(
      try PairingFixtures.qrPayload(hostIdentityFingerprint: Data(repeating: 0x01, count: 31))
    ) { error in
      XCTAssertEqual(
        error as? SecureWireValidationError, .invalidField(name: "hostIdentityFingerprint"))
    }
    XCTAssertThrowsError(
      try PairingFixtures.qrPayload(tlsSPKIFingerprint: Data(repeating: 0x01, count: 33))
    ) { error in
      XCTAssertEqual(error as? SecureWireValidationError, .invalidField(name: "tlsSPKIFingerprint"))
    }
    XCTAssertThrowsError(
      try PairingFixtures.qrPayload(bootstrapSecret: Data(repeating: 0x01, count: 16))
    ) { error in
      XCTAssertEqual(error as? SecureWireValidationError, .invalidField(name: "bootstrapSecret"))
    }
  }
}
