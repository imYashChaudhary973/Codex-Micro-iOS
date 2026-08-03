import CompanionProtocol
import Foundation
import XCTest

/// Golden fixtures and adversarial decoding for the Step 2.8 observation
/// payload schemas that bind ``SecureObservationDelivery``'s opaque bytes.
final class ObservationPayloadTests: XCTestCase {
  private static let snapshotJSON =
    #"{"generatedAtEpochSeconds":1000,"threads":[{"activeTurnID":"turn-1","lastTurnID":"turn-1","lastTurnStatus":"inProgress","projectID":"project-a","status":"active","threadID":"thread-a"},{"projectID":"project-b","status":"idle","threadID":"thread-b"}]}"#

  private static let eventBatchJSON =
    #"{"events":[{"kind":"threadUpdated","projectID":"project-a","sequence":1,"threadID":"thread-a"},{"kind":"threadUpdated","projectID":"project-b","sequence":4,"threadID":"thread-b"}]}"#

  // MARK: - Golden fixtures

  func testSnapshotPayloadMatchesGoldenAndRoundTrips() throws {
    let payload = try SecureObservationSnapshot(
      generatedAtEpochSeconds: 1_000,
      threads: [
        try ObservedThreadState(
          threadID: "thread-a", projectID: "project-a", status: .active,
          activeTurnID: "turn-1", lastTurnID: "turn-1", lastTurnStatus: .inProgress),
        try ObservedThreadState(
          threadID: "thread-b", projectID: "project-b", status: .idle,
          activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil),
      ]
    )

    let encoded = try SecureFixtures.encoder().encode(payload)
    XCTAssertEqual(String(decoding: encoded, as: UTF8.self), Self.snapshotJSON)

    let decoded = try JSONDecoder().decode(
      SecureObservationSnapshot.self, from: Data(Self.snapshotJSON.utf8))
    XCTAssertEqual(decoded, payload)
    XCTAssertEqual(
      String(decoding: try SecureFixtures.encoder().encode(decoded), as: UTF8.self),
      Self.snapshotJSON
    )
  }

  func testEventBatchPayloadMatchesGoldenAndRoundTrips() throws {
    let payload = try SecureObservationEventBatch(events: [
      try SecureObservationEvent(
        sequence: 1, kind: .threadUpdated, threadID: "thread-a", projectID: "project-a"),
      try SecureObservationEvent(
        sequence: 4, kind: .threadUpdated, threadID: "thread-b", projectID: "project-b"),
    ])

    let encoded = try SecureFixtures.encoder().encode(payload)
    XCTAssertEqual(String(decoding: encoded, as: UTF8.self), Self.eventBatchJSON)

    let decoded = try JSONDecoder().decode(
      SecureObservationEventBatch.self, from: Data(Self.eventBatchJSON.utf8))
    XCTAssertEqual(decoded, payload)
  }

  func testDeliveryCarriesAPayloadInsideItsDeclaredBound() throws {
    let payload = try SecureFixtures.encoder().encode(
      try SecureObservationEventBatch(events: [
        try SecureObservationEvent(
          sequence: 1, kind: .threadUpdated, threadID: "thread-a", projectID: "project-a")
      ])
    )

    let delivery = try SecureObservationDelivery(
      subscriptionID: SecureFixtures.subscriptionID,
      kind: .event,
      cursor: try SecureFixtures.cursor(),
      payload: payload
    )

    XCTAssertLessThanOrEqual(
      delivery.payload.count, SecureTransportLimits.maxObservationPayloadBytes)
  }

  // MARK: - Adversarial decoding

  func testPayloadsRejectUnknownFields() {
    let cases = [
      #"{"generatedAtEpochSeconds":1000,"latestSequence":9,"threads":[]}"#,
      #"{"generatedAtEpochSeconds":1000,"threads":[{"projectID":"p","status":"idle","threadID":"t","cwd":"/x"}]}"#,
    ]
    for json in cases {
      XCTAssertThrowsError(
        try JSONDecoder().decode(SecureObservationSnapshot.self, from: Data(json.utf8)),
        json
      )
    }
    XCTAssertThrowsError(
      try JSONDecoder().decode(
        SecureObservationEventBatch.self,
        from: Data(#"{"events":[],"latestSequence":3}"#.utf8)
      )
    )
  }

  func testSnapshotRejectsDuplicateUnsortedAndOversizedThreadSets() throws {
    let duplicate = try ObservedThreadState(
      threadID: "thread-a", projectID: "project-a", status: .idle,
      activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil)
    let other = try ObservedThreadState(
      threadID: "thread-b", projectID: "project-a", status: .idle,
      activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil)

    XCTAssertThrowsError(
      try SecureObservationSnapshot(
        generatedAtEpochSeconds: 1_000, threads: [duplicate, duplicate]))
    XCTAssertThrowsError(
      try SecureObservationSnapshot(generatedAtEpochSeconds: 1_000, threads: [other, duplicate]))

    let overCount = SecureObservationLimits.maxSnapshotThreadCount + 1
    let many = try (0..<overCount).map {
      try ObservedThreadState(
        threadID: String(format: "thread-%04d", $0), projectID: "project-a", status: .idle,
        activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil)
    }
    XCTAssertThrowsError(
      try SecureObservationSnapshot(generatedAtEpochSeconds: 1_000, threads: many))
  }

  func testEventBatchRejectsEmptyOversizedAndNonIncreasingRuns() throws {
    func event(_ sequence: UInt64) throws -> SecureObservationEvent {
      try SecureObservationEvent(
        sequence: sequence, kind: .threadUpdated, threadID: "thread-a", projectID: "project-a")
    }

    XCTAssertThrowsError(try SecureObservationEventBatch(events: []))
    XCTAssertThrowsError(try SecureObservationEventBatch(events: [try event(2), try event(1)]))
    XCTAssertThrowsError(try SecureObservationEventBatch(events: [try event(2), try event(2)]))

    let overCount = SecureObservationLimits.maxEventBatchCount + 1
    let many = try (1...overCount).map { try event(UInt64($0)) }
    XCTAssertThrowsError(try SecureObservationEventBatch(events: many))
    XCTAssertNoThrow(try SecureObservationEventBatch(events: Array(many.dropLast())))
  }

  func testIdentifierBoundsAreEnforcedOnEveryOpaqueField() {
    let tooLong = String(repeating: "x", count: 129)
    let control = "thread\u{0007}a"

    XCTAssertThrowsError(
      try ObservedThreadState(
        threadID: tooLong, projectID: "project-a", status: .idle,
        activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil))
    XCTAssertThrowsError(
      try ObservedThreadState(
        threadID: "thread-a", projectID: control, status: .idle,
        activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil))
    XCTAssertThrowsError(
      try ObservedThreadState(
        threadID: "thread-a", projectID: "project-a", status: .idle,
        activeTurnID: tooLong, lastTurnID: nil, lastTurnStatus: nil))
    XCTAssertThrowsError(
      try ObservedThreadState(
        threadID: "thread-a", projectID: "project-a", status: .idle,
        activeTurnID: nil, lastTurnID: "", lastTurnStatus: nil))
    XCTAssertThrowsError(
      try SecureObservationEvent(
        sequence: 0, kind: .threadUpdated, threadID: "thread-a", projectID: "project-a"))
  }

  func testEventKindVocabularyIsClosed() {
    XCTAssertEqual(SecureObservationEventKind.allCases, [.threadUpdated])
    XCTAssertThrowsError(
      try JSONDecoder().decode(
        SecureObservationEvent.self,
        from: Data(
          #"{"kind":"approvalRequested","projectID":"p","sequence":1,"threadID":"t"}"#.utf8)
      )
    )
  }

  func testObservationSchemaDeclaresNoApprovalField() throws {
    let snapshot = try SecureObservationSnapshot(
      generatedAtEpochSeconds: 1_000,
      threads: [
        try ObservedThreadState(
          threadID: "thread-a", projectID: "project-a", status: .idle,
          activeTurnID: nil, lastTurnID: nil, lastTurnStatus: nil)
      ]
    )

    let fields = Set(
      (try JSONSerialization.jsonObject(with: try SecureFixtures.encoder().encode(snapshot))
        as? [String: Any] ?? [:]).keys)

    XCTAssertEqual(fields, ["generatedAtEpochSeconds", "threads"])
  }
}
