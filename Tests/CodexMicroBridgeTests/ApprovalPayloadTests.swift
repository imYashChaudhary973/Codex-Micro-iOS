import CompanionProtocol
import Foundation
import XCTest

/// The device-facing approval payload.
///
/// The hardest decision in this step is what a phone is told about what it is
/// approving. An approval the user cannot evaluate trains them to press accept
/// because that is the only way to make the prompt go away; but approval
/// content *is* workspace content, which the observation surface deliberately
/// never carries. The payload resolves that by defaulting closed and letting
/// the Mac opt in.
final class ApprovalPayloadTests: XCTestCase {

  /// Content is absent unless the Mac chose to include it, and the payload
  /// says which case it is in so "approve blind" is a visible choice rather
  /// than an accident.
  func testContentIsAbsentByDefaultAndTheFlagSaysSo() throws {
    let closed = try request()
    let disclosed = try request(summary: "Run: swift test")

    XCTAssertNil(closed.summary)
    XCTAssertFalse(closed.disclosesContent)
    XCTAssertTrue(disclosed.disclosesContent)
  }

  /// The summary is bounded so it cannot become a channel for exporting a
  /// file one approval at a time.
  func testAnOversizedSummaryIsRejected() {
    XCTAssertThrowsError(
      try request(summary: String(repeating: "x", count: 500)))
  }

  /// An approval with no available decision is not a decision; showing one
  /// would present a control that cannot do anything.
  func testAnApprovalWithNoDecisionsIsRejected() {
    XCTAssertThrowsError(try request(decisions: []))
  }

  /// Offering the same decision twice would render two identical keys, one of
  /// which is meaningless.
  func testDuplicateDecisionsAreRejected() {
    XCTAssertThrowsError(try request(decisions: [.approveOnce, .approveOnce]))
  }

  func testAnEmptyDigestIsRejected() {
    XCTAssertThrowsError(try request(digest: ""))
  }

  func testThePayloadRoundTripsAndRejectsUnknownFields() throws {
    let original = try request(summary: "Run: swift test")
    let encoded = try JSONEncoder().encode(original)

    XCTAssertEqual(
      try JSONDecoder().decode(SecureApprovalRequest.self, from: encoded), original)

    var object =
      try JSONSerialization.jsonObject(with: encoded) as? [String: Any] ?? [:]
    object["surprise"] = true
    let tampered = try JSONSerialization.data(withJSONObject: object)
    XCTAssertThrowsError(
      try JSONDecoder().decode(SecureApprovalRequest.self, from: tampered))
  }

  /// Batches are bounded and cannot carry the same request twice, which would
  /// let one approval be resolved from two keys.
  func testBatchesAreBoundedAndDeduplicated() throws {
    let many = try (0..<20).map { try request(id: "request-\($0)") }
    XCTAssertThrowsError(
      try SecureApprovalBatch(generatedAtEpochSeconds: 1, pending: many))

    let duplicated = [try request(id: "r"), try request(id: "r")]
    XCTAssertThrowsError(
      try SecureApprovalBatch(generatedAtEpochSeconds: 1, pending: duplicated))
  }

  private func request(
    id: String = "request-1",
    digest: String = "digest-1",
    decisions: [CompanionApprovalDecision] = [.approveOnce, .decline],
    summary: String? = nil
  ) throws -> SecureApprovalRequest {
    try SecureApprovalRequest(
      requestID: id, threadID: "thread-a", projectID: "project-a", kind: .command,
      availableDecisions: decisions, requestDigest: digest,
      expiresAtEpochSeconds: 10_000, summary: summary)
  }
}
