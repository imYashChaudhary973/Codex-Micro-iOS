import CompanionProtocol
import Foundation
import XCTest

@testable import CompanionCrypto

/// Pairing entropy, constant-time comparison, and the fixed policy values
/// (plan §2 invariant 7, plan §9).
final class PairingPrimitivesTests: XCTestCase {
  func testFixedPolicyValues() {
    XCTAssertEqual(PairingPolicy.sessionLifetimeSeconds, 300)
    XCTAssertEqual(PairingPolicy.bootstrapSecretByteCount, 32)
    XCTAssertEqual(PairingPolicy.nonceByteCount, 32)
    XCTAssertEqual(PairingPolicy.bootstrapSecretByteCount * 8, 256)
    XCTAssertEqual(PairingPolicy.nonceByteCount * 8, 256)
    XCTAssertGreaterThan(PairingPolicy.maxFailedClaimAttempts, 0)
  }

  func testSystemRandomSourceReturnsRequestedLengths() throws {
    let source = SystemPairingRandomSource()
    for count in [8, 32, 64] {
      XCTAssertEqual(try source.randomBytes(count: count).count, count)
    }
    XCTAssertThrowsError(try source.randomBytes(count: 0))
    XCTAssertThrowsError(try source.randomBytes(count: 12))
  }

  func testSystemRandomSourceEntropyShape() throws {
    let source = SystemPairingRandomSource()
    var samples: Set<Data> = []
    for _ in 0..<32 {
      let bytes = try source.randomBytes(count: PairingPolicy.bootstrapSecretByteCount)
      XCTAssertEqual(bytes.count, 32)
      XCTAssertFalse(bytes.allSatisfy { $0 == bytes[bytes.startIndex] }, "constant output")
      XCTAssertNotEqual(bytes, Data(count: 32))
      XCTAssertGreaterThan(Set(bytes).count, 8, "implausibly low byte diversity")
      samples.insert(bytes)
    }
    XCTAssertEqual(samples.count, 32, "repeated 256-bit draws must not collide")
  }

  func testConstantTimeComparisonResults() {
    let secret = Data(repeating: 0xB5, count: 32)
    XCTAssertTrue(constantTimeEquals(secret, Data(repeating: 0xB5, count: 32)))
    XCTAssertTrue(constantTimeEquals(Data(), Data()))

    for index in 0..<secret.count {
      var mutated = secret
      mutated[index] ^= 0x01
      XCTAssertFalse(constantTimeEquals(secret, mutated), "byte \(index) must be compared")
    }
    XCTAssertFalse(constantTimeEquals(secret, secret.dropLast()))
    XCTAssertFalse(constantTimeEquals(secret, secret + Data([0x00])))
    XCTAssertFalse(constantTimeEquals(secret, Data()))
  }

  /// Result equality alone is also satisfied by `==`, so this asserts the
  /// property that matters: the number of byte comparisons is exactly the
  /// length regardless of where the first difference is. An early return
  /// fails here.
  func testConstantTimeComparisonVisitsEveryByteRegardlessOfDifferencePosition() {
    let secret = Data(repeating: 0xB5, count: PairingPolicy.bootstrapSecretByteCount)

    func visitedIndices(comparedTo other: Data) -> [Int] {
      var visited: [Int] = []
      _ = constantTimeEquals(secret, other, probe: { visited.append($0) })
      return visited
    }

    let expected = Array(0..<secret.count)
    XCTAssertEqual(visitedIndices(comparedTo: secret), expected, "equal inputs")

    for index in [0, 1, secret.count / 2, secret.count - 1] {
      var mutated = secret
      mutated[index] ^= 0xFF
      XCTAssertEqual(
        visitedIndices(comparedTo: mutated),
        expected,
        "a difference at byte \(index) must not shorten the comparison"
      )
    }

    var allDifferent = Data(repeating: 0x4A, count: secret.count)
    allDifferent[0] = 0x00
    XCTAssertEqual(visitedIndices(comparedTo: allDifferent), expected, "fully differing inputs")

    // Length inequality is the one early exit, and it is not secret: every
    // pairing secret has a fixed size the wire schema already validated.
    XCTAssertEqual(visitedIndices(comparedTo: secret.dropLast()), [])
  }

  func testClosedReasonVocabularyIsContentFree() {
    for reason in PairingClosedReason.allCases {
      XCTAssertFalse(reason.rawValue.isEmpty)
      XCTAssertTrue(reason.rawValue.allSatisfy(\.isASCII))
      XCTAssertFalse(reason.rawValue.contains(" "))
    }
    XCTAssertEqual(
      Set(PairingClosedReason.allCases.map(\.rawValue)).count,
      PairingClosedReason.allCases.count)
  }

  func testInitialGrantIntentIsObserveWithEmptyProjectScope() {
    let intent = PairedDeviceGrantIntent.initial
    XCTAssertEqual(intent.capabilities, [.observe])
    XCTAssertTrue(intent.projectAllowlist.isEmpty)
    XCTAssertEqual(PairedDeviceCapabilityIntent.allCases, [.observe])
  }
}
