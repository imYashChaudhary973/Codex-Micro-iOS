import CompanionProtocol
import Foundation
import NIOHTTP1
import XCTest

@testable import MacBridgeServer

/// Exact HTTP upgrade policy matrix (ADR §9). Each case mutates exactly one
/// field of a known-good request so a rejection is attributable.
final class ListenerUpgradePolicyTests: XCTestCase {
  private let policy = ListenerUpgradePolicy()

  private func rejection(
    of head: HTTPRequestHead
  ) -> ListenerUpgradeRejection? {
    switch policy.evaluate(head) {
    case .success:
      return nil
    case .failure(let rejection):
      return rejection
    }
  }

  func testWellFormedRequestUpgradesAndNegotiatesOnlyTheSubprotocol() throws {
    let result = policy.evaluate(UpgradeRequestFixture.head())
    guard case .success(let headers) = result else {
      return XCTFail("expected the canonical request to upgrade")
    }
    XCTAssertEqual(headers["Sec-WebSocket-Protocol"], [ListenerUpgradePolicy.subprotocol])
    XCTAssertTrue(headers["Sec-WebSocket-Extensions"].isEmpty)
    XCTAssertEqual(headers.count, 1)
  }

  func testOnlyGETIsAccepted() {
    for method in [HTTPMethod.POST, .PUT, .DELETE, .HEAD, .OPTIONS, .PATCH] {
      XCTAssertEqual(rejection(of: UpgradeRequestFixture.head(method: method)), .method)
    }
  }

  func testOnlyHTTP11IsAccepted() {
    XCTAssertEqual(
      rejection(of: UpgradeRequestFixture.head(version: .http1_0)),
      .version
    )
  }

  func testOnlyTheExactPathIsAccepted() {
    let denied = [
      "/",
      "/codex-micro",
      "/codex-micro/bridge",
      "/codex-micro/bridge/v2",
      ListenerUpgradePolicy.path + "/",
      ListenerUpgradePolicy.path.uppercased(),
    ]
    for uri in denied {
      XCTAssertEqual(rejection(of: UpgradeRequestFixture.head(uri: uri)), .pathOrQuery, uri)
    }
  }

  func testAnyQueryStringIsRejected() {
    let denied = [
      ListenerUpgradePolicy.path + "?",
      ListenerUpgradePolicy.path + "?a=1",
      ListenerUpgradePolicy.path + "?sentinel=thread-42",
      ListenerUpgradePolicy.path + "#fragment",
    ]
    for uri in denied {
      XCTAssertEqual(rejection(of: UpgradeRequestFixture.head(uri: uri)), .pathOrQuery, uri)
    }
  }

  func testOriginMustBeTheExactSingleValue() {
    XCTAssertEqual(
      rejection(
        of: UpgradeRequestFixture.head { headers in
          headers.replaceOrAdd(name: "Origin", value: "https://evil.invalid")
        }),
      .origin
    )
    XCTAssertEqual(
      rejection(of: UpgradeRequestFixture.head { $0.remove(name: "Origin") }),
      .origin
    )
    XCTAssertEqual(
      rejection(
        of: UpgradeRequestFixture.head { headers in
          headers.add(name: "Origin", value: ListenerUpgradePolicy.origin)
        }),
      .origin
    )
  }

  func testSubprotocolMustBeTheExactSingleToken() {
    XCTAssertEqual(
      rejection(
        of: UpgradeRequestFixture.head { headers in
          headers.replaceOrAdd(name: "Sec-WebSocket-Protocol", value: "chat")
        }),
      .protocolToken
    )
    XCTAssertEqual(
      rejection(
        of: UpgradeRequestFixture.head { headers in
          headers.replaceOrAdd(
            name: "Sec-WebSocket-Protocol",
            value: "\(ListenerUpgradePolicy.subprotocol), chat"
          )
        }),
      .protocolToken
    )
    XCTAssertEqual(
      rejection(of: UpgradeRequestFixture.head { $0.remove(name: "Sec-WebSocket-Protocol") }),
      .protocolToken
    )
  }

  func testSubprotocolIsComparedCaseSensitively() {
    // ADR §9 fixes the subprotocol as an exact single value.
    for variant in [
      ListenerUpgradePolicy.subprotocol.uppercased(),
      ListenerUpgradePolicy.subprotocol.capitalized,
      "Codex-Micro.Bridge.V1",
    ] {
      XCTAssertEqual(
        rejection(
          of: UpgradeRequestFixture.head { headers in
            headers.replaceOrAdd(name: "Sec-WebSocket-Protocol", value: variant)
          }),
        .protocolToken,
        variant
      )
    }
  }

  func testConnectionAndUpgradeTokensStayCaseInsensitive() throws {
    // RFC 9110 defines these tokens case-insensitively; only the values the
    // ADR fixes exactly are compared case-sensitively.
    let head = UpgradeRequestFixture.head { headers in
      headers.replaceOrAdd(name: "Upgrade", value: "WebSocket")
      headers.replaceOrAdd(name: "Connection", value: "UPGRADE")
    }
    guard case .success = policy.evaluate(head) else {
      return XCTFail("token case must not change the outcome")
    }
  }

  func testWebSocketVersionMustBe13() {
    for version in ["12", "14", "8", "", "13, 14"] {
      XCTAssertEqual(
        rejection(
          of: UpgradeRequestFixture.head { headers in
            headers.replaceOrAdd(name: "Sec-WebSocket-Version", value: version)
          }),
        .version,
        version
      )
    }
  }

  func testWebSocketKeyMustBeSixteenDecodedBytes() {
    let denied = [
      "",
      "not-base64!!",
      Data(repeating: 0x01, count: 15).base64EncodedString(),
      Data(repeating: 0x01, count: 17).base64EncodedString(),
    ]
    for key in denied {
      XCTAssertEqual(
        rejection(
          of: UpgradeRequestFixture.head { headers in
            headers.replaceOrAdd(name: "Sec-WebSocket-Key", value: key)
          }),
        .requiredHeader,
        key
      )
    }
  }

  func testRequiredHeadersMustOccurExactlyOnce() {
    for name in ["Upgrade", "Connection", "Sec-WebSocket-Version", "Sec-WebSocket-Key"] {
      XCTAssertNotNil(
        rejection(of: UpgradeRequestFixture.head { $0.remove(name: name) }),
        "missing \(name) must be rejected"
      )
      let duplicated = UpgradeRequestFixture.head { headers in
        let existing = headers[name].first ?? ""
        headers.add(name: name, value: existing)
      }
      XCTAssertNotNil(rejection(of: duplicated), "duplicate \(name) must be rejected")
    }
  }

  func testHostMustBePresentAndSingle() {
    XCTAssertEqual(
      rejection(of: UpgradeRequestFixture.head { $0.remove(name: "Host") }),
      .host
    )
    XCTAssertEqual(
      rejection(
        of: UpgradeRequestFixture.head { headers in
          headers.replaceOrAdd(name: "Host", value: "")
        }),
      .host
    )
  }

  func testHeaderNamesOutsideTheAllowlistAreRejected() {
    let denied = ["X-Forwarded-For", "Authorization", "Cookie", "Sec-WebSocket-Accept", "Referer"]
    for name in denied {
      XCTAssertEqual(
        rejection(of: UpgradeRequestFixture.head { $0.add(name: name, value: "v") }),
        .headerName,
        name
      )
    }
  }

  func testHeaderCountCeilingIsEnforced() {
    let head = UpgradeRequestFixture.head { headers in
      // The fixture has 7 fields; add allowlisted names until past 16.
      for _ in 0..<10 {
        headers.add(name: "Pragma", value: "no-cache")
      }
    }
    XCTAssertEqual(rejection(of: head), .headerCount)
  }

  func testSingleHeaderFieldCeilingIsEnforced() {
    let oversized = String(repeating: "a", count: SecureTransportLimits.maxHeaderFieldBytes + 1)
    XCTAssertEqual(
      rejection(of: UpgradeRequestFixture.head { $0.add(name: "User-Agent", value: oversized) }),
      .headerSize
    )
  }

  func testTotalHeaderSizeCeilingIsEnforced() {
    let chunk = String(repeating: "a", count: 3_000)
    let head = UpgradeRequestFixture.head { headers in
      headers.add(name: "User-Agent", value: chunk)
      headers.add(name: "Accept-Language", value: chunk)
      headers.add(name: "Accept-Encoding", value: chunk)
    }
    XCTAssertEqual(rejection(of: head), .headerSize)
  }

  func testExactlyTheURLSessionDeflateOfferIsToleratedAndNeverEchoed() throws {
    let head = UpgradeRequestFixture.head { headers in
      headers.add(name: "Sec-WebSocket-Extensions", value: "permessage-deflate")
    }
    guard case .success(let response) = policy.evaluate(head) else {
      return XCTFail("the exact URLSession offer must be tolerated")
    }
    XCTAssertTrue(response["Sec-WebSocket-Extensions"].isEmpty)
  }

  func testOtherCompressionOffersAreRejected() {
    let denied = [
      "permessage-deflate; client_max_window_bits",
      "x-webkit-deflate-frame",
      "permessage-deflate, x-custom",
      "PERMESSAGE-DEFLATE",
    ]
    for offer in denied {
      XCTAssertEqual(
        rejection(
          of: UpgradeRequestFixture.head { $0.add(name: "Sec-WebSocket-Extensions", value: offer) }),
        .websocketExtensions,
        offer
      )
    }
  }

  func testConnectionHeaderMustCarryTheUpgradeToken() {
    XCTAssertEqual(
      rejection(
        of: UpgradeRequestFixture.head { headers in
          headers.replaceOrAdd(name: "Connection", value: "keep-alive")
        }),
      .requiredHeader
    )
  }

  func testUpgradeHeaderMustNameWebSocket() {
    XCTAssertEqual(
      rejection(
        of: UpgradeRequestFixture.head { headers in
          headers.replaceOrAdd(name: "Upgrade", value: "h2c")
        }),
      .requiredHeader
    )
  }

  func testUpgradeRejectionVocabularyCarriesNoPeerContent() {
    for rejection in ListenerUpgradeRejection.allCases {
      XCTAssertFalse(rejection.rawValue.isEmpty)
      XCTAssertEqual(rejection.rawValue, rejection.rawValue.trimmingCharacters(in: .whitespaces))
    }
  }
}
