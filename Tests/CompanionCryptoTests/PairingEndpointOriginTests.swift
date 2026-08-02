import CompanionProtocol
import Foundation
import XCTest

@testable import CompanionCrypto

/// Normalized direct-LAN endpoint origins (ADR §8/§12). Pairing compares
/// endpoints by normalized equality only, so every alias must collapse and
/// every ambiguous form must fail closed.
final class PairingEndpointOriginTests: XCTestCase {
  private func normalized(_ raw: String) throws -> String {
    try PairingEndpointOrigin(raw).normalized
  }

  private func assertRejects(
    _ raw: String,
    _ expected: PairingEndpointOriginError,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertThrowsError(try PairingEndpointOrigin(raw), raw, file: file, line: line) { error in
      XCTAssertEqual(error as? PairingEndpointOriginError, expected, raw, file: file, line: line)
    }
  }

  // MARK: - Normalization equality

  func testSchemeAndHostCaseAreNormalized() throws {
    XCTAssertEqual(try normalized("WSS://192.168.4.20:8443"), "wss://192.168.4.20:8443")
    XCTAssertEqual(
      try PairingEndpointOrigin("WsS://[2001:DB8::1]:8443"),
      try PairingEndpointOrigin("wss://[2001:db8::1]:8443")
    )
  }

  func testDefaultPortIsElided() throws {
    XCTAssertEqual(try normalized("wss://192.168.4.20:443"), "wss://192.168.4.20")
    XCTAssertEqual(
      try PairingEndpointOrigin("wss://192.168.4.20:443"),
      try PairingEndpointOrigin("wss://192.168.4.20")
    )
    XCTAssertEqual(try normalized("wss://[fd00::1]:443"), "wss://[fd00::1]")
    XCTAssertNotEqual(
      try PairingEndpointOrigin("wss://192.168.4.20:8443"),
      try PairingEndpointOrigin("wss://192.168.4.20")
    )
  }

  func testIPv6IsRenderedInCanonicalCompressedForm() throws {
    XCTAssertEqual(
      try normalized("wss://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443"),
      "wss://[2001:db8::1]:8443"
    )
    XCTAssertEqual(try normalized("wss://[0000:0000:0000:0000:0000:0000:0000:0001]"), "wss://[::1]")
    XCTAssertEqual(try normalized("wss://[FD00:0:0:0:0:0:0:ABCD]"), "wss://[fd00::abcd]")
  }

  func testLongestZeroRunIsCompressedLeftmostOnTie() {
    // Two equal-length runs: the leftmost is compressed (RFC 5952).
    let tie = PairingEndpointOriginNormalizer.renderIPv6([
      0x20, 0x01, 0, 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x02, 0x00, 0x03,
    ])
    XCTAssertEqual(tie, "2001::1:0:0:2:3")

    // A single zero group is never compressed.
    let single = PairingEndpointOriginNormalizer.renderIPv6([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
    ])
    XCTAssertEqual(single, "2001:db8:0:1:2:3:4:5")
  }

  func testDistinctAddressesDoNotCompareEqual() throws {
    XCTAssertNotEqual(
      try PairingEndpointOrigin("wss://192.168.4.20:8443"),
      try PairingEndpointOrigin("wss://192.168.4.21:8443")
    )
    XCTAssertNotEqual(
      try PairingEndpointOrigin("wss://[fd00::1]:8443"),
      try PairingEndpointOrigin("wss://[fd00::2]:8443")
    )
  }

  // MARK: - Rejections

  func testHostnamesAreRejected() {
    assertRejects("wss://mac.local:8443", .hostNotNumericAddress)
    assertRejects("wss://codex-micro:8443", .hostNotNumericAddress)
    assertRejects("wss://192.168.4.20.nip.io", .hostNotNumericAddress)
  }

  func testWildcardAddressesAreRejected() {
    assertRejects("wss://0.0.0.0:8443", .wildcardAddress)
    assertRejects("wss://[::]:8443", .wildcardAddress)
    assertRejects("wss://[0:0:0:0:0:0:0:0]", .wildcardAddress)
  }

  func testPathQueryFragmentAndUserinfoAreRejected() {
    assertRejects("wss://192.168.4.20:8443/pair", .unsupportedComponent)
    assertRejects("wss://192.168.4.20:8443?token=1", .unsupportedComponent)
    assertRejects("wss://192.168.4.20:8443#frag", .unsupportedComponent)
    assertRejects("wss://user@192.168.4.20:8443", .unsupportedComponent)
    assertRejects("wss://192.168.4.20:8443/", .unsupportedComponent)
  }

  func testWrongOrMissingSchemeIsRejected() {
    assertRejects("ws://192.168.4.20:8443", .unsupportedScheme)
    assertRejects("https://192.168.4.20:8443", .unsupportedScheme)
    assertRejects("192.168.4.20:8443", .unsupportedScheme)
  }

  func testPortBoundsAreEnforced() {
    assertRejects("wss://192.168.4.20:0", .invalidPort)
    assertRejects("wss://192.168.4.20:65536", .invalidPort)
    assertRejects("wss://192.168.4.20:08443", .invalidPort)
    assertRejects("wss://192.168.4.20:", .invalidPort)
    assertRejects("wss://192.168.4.20:http", .invalidPort)
    assertRejects("wss://[fd00::1]:0", .invalidPort)
  }

  func testNonCanonicalIPv4FormsAreRejected() {
    assertRejects("wss://192.168.004.020:8443", .hostNotNumericAddress)
    assertRejects("wss://192.168.1:8443", .hostNotNumericAddress)
    assertRejects("wss://192.168.1.256:8443", .hostNotNumericAddress)
    assertRejects("wss://192.168.1.1.1:8443", .hostNotNumericAddress)
    assertRejects("wss://0xc0.0xa8.0x04.0x14:8443", .hostNotNumericAddress)
  }

  func testAmbiguousIPv6FormsAreRejected() {
    assertRejects("wss://[::ffff:c0a8:414]:8443", .aliasedAddress)
    assertRejects("wss://[::ffff:192.168.4.20]:8443", .hostNotNumericAddress)
    assertRejects("wss://[fd00::1%en0]:8443", .hostNotNumericAddress)
    assertRejects("wss://[1::2::3]:8443", .hostNotNumericAddress)
    assertRejects("wss://[fd00:0:0:0:0:0:0:0:1]:8443", .hostNotNumericAddress)
    assertRejects("wss://[12345::1]:8443", .hostNotNumericAddress)
  }

  func testBracketingMustMatchTheAddressFamily() {
    assertRejects("wss://[192.168.4.20]:8443", .hostNotNumericAddress)
    assertRejects("wss://fd00::1:8443", .hostNotNumericAddress)
    assertRejects("wss://[fd00::1:8443", .hostNotNumericAddress)
    assertRejects("wss://fd00::1]:8443", .hostNotNumericAddress)
  }

  func testMalformedOriginsAreRejected() {
    assertRejects("", .malformedOrigin)
    assertRejects("wss://192.168.4.20:8443 ", .malformedOrigin)
    assertRejects("wss://192.168.4.20\u{0}:8443", .malformedOrigin)
    assertRejects(
      "wss://192.168.4.20:8443" + String(repeating: "0", count: 128), .malformedOrigin)
    XCTAssertEqual(SecureTransportLimits.maxEndpointOriginBytes, 128)
  }
}
