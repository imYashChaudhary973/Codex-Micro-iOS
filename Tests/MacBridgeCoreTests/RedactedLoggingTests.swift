import CodexAppServer
import CompanionProtocol
import Foundation
import XCTest

@testable import MacBridgeCore

/// Content-leak contracts for the redacted logger: sentinel strings injected
/// through every raw-event surface must never reach serialized log bytes.
final class RedactedLoggingTests: XCTestCase {
  private static let sentinels = [
    "SENTINEL_PROMPT",
    "SENTINEL_COMMAND",
    "/sentinel/private/path",
    "SENTINEL_DELTA",
    "SENTINEL_ERROR",
    "SENTINEL_METHOD",
    "sentinel-thread",
    "sentinel-turn",
  ]

  func testSentinelLadenAppServerEventsNeverReachLogBytes() throws {
    let sentinelEvents: [AppServerEvent] = [
      .notification(
        method: "item/agentMessage/delta",
        params: .object([
          "threadId": .string("sentinel-thread"),
          "turnId": .string("sentinel-turn"),
          "delta": .string("SENTINEL_DELTA"),
        ])
      ),
      .notification(
        method: "turn/completed",
        params: .object([
          "turn": .object([
            "id": .string("sentinel-turn"),
            "status": .string("failed"),
            "error": .object(["message": .string("SENTINEL_ERROR")]),
          ])
        ])
      ),
      .notification(
        method: "SENTINEL_METHOD",
        params: .object(["prompt": .string("SENTINEL_PROMPT")])
      ),
      .serverRequest(
        id: 42,
        method: "item/commandExecution/requestApproval",
        params: .object([
          "threadId": .string("sentinel-thread"),
          "turnId": .string("sentinel-turn"),
          "itemId": .string("item-1"),
          "command": .string("SENTINEL_COMMAND"),
          "cwd": .string("/sentinel/private/path"),
        ])
      ),
      .serverRequest(
        id: 43,
        method: "SENTINEL_METHOD",
        params: .object(["command": .string("SENTINEL_COMMAND")])
      ),
      .protocolWarning("SENTINEL_ERROR in warning text"),
    ]

    let serialized = try serializeEntries(
      sentinelEvents.map(RedactedLogger.describe)
    )
    for sentinel in Self.sentinels {
      XCTAssertFalse(
        serialized.contains(sentinel),
        "Log bytes leaked sentinel \(sentinel)."
      )
    }
    XCTAssertTrue(serialized.contains("event.notification.unknown"))
    XCTAssertTrue(serialized.contains("event.request.unknown"))
    XCTAssertTrue(serialized.contains("event.protocolWarning"))
  }

  func testRecoveryEventsReduceThreadIDsToCounts() throws {
    let recoveryEvents: [CodexRecoveryEvent] = [
      .runtimeState(.degraded(.connectionClosed)),
      .recoveryStarted(attempt: 2),
      .rebuilt(
        threadIDs: ["sentinel-thread"],
        droppedThreadIDs: ["sentinel-thread-2"]
      ),
    ]

    let serialized = try serializeEntries(
      recoveryEvents.map(RedactedLogger.describe)
    )
    XCTAssertFalse(serialized.contains("sentinel-thread"))
    XCTAssertTrue(serialized.contains("runtime.degraded.connectionClosed"))
    XCTAssertTrue(serialized.contains("recovery.rebuilt"))
    XCTAssertTrue(serialized.contains(#""rebuilt":1"#))
    XCTAssertTrue(serialized.contains(#""dropped":1"#))
  }

  func testWholeVocabularySerializesOnlyClosedCodes() throws {
    let vocabulary: [BridgeLogEvent] = [
      .runtimeStateChanged(
        .ready(.init(codexVersion: "0.146.0", schemaDigest: "digest"))),
      .runtimeStateChanged(.unsupported(.schemaMismatch)),
      .recoveryStarted(attempt: 1),
      .recoveryFailed(attempt: 1),
      .recoveryRebuilt(rebuiltThreadCount: 3, droppedThreadCount: 0),
      .appServerNotification(.turnStarted),
      .appServerRequest(.permissionsRequestApproval),
      .protocolWarning,
      .approvalIngested(kind: .fileChange),
      .approvalRejected(reason: .digestMismatch),
      .approvalResponseSent(decision: .approveOnce),
      .approvalConfirmed,
      .approvalOutcomeUnknown,
      .commandRegistered(kind: .resolveApproval),
      .commandReplayed(kind: .resolveApproval),
      .commandFinished(state: .succeeded, resultCode: .completed),
      .ledgerOperationFailed(operation: .finish),
    ]

    let sink = CapturingLogSink()
    let logger = RedactedLogger(sink: sink)
    for event in vocabulary {
      logger.log(event, at: Date(timeIntervalSince1970: 1_754_000_000))
    }

    let codes = sink.entries().map(\.code)
    XCTAssertEqual(codes.count, vocabulary.count)
    XCTAssertTrue(codes.contains("runtime.ready"))
    XCTAssertTrue(codes.contains("runtime.unsupported.schemaMismatch"))
    XCTAssertTrue(codes.contains("event.notification.turn/started"))
    XCTAssertTrue(codes.contains("approval.rejected.digestMismatch"))
    XCTAssertTrue(codes.contains("approval.responseSent.approveOnce"))
    XCTAssertTrue(codes.contains("command.finished.succeeded.completed"))
    XCTAssertTrue(codes.contains("ledger.operationFailed.finish"))

    let serialized = try serializeEntries(vocabulary)
    for sentinel in Self.sentinels {
      XCTAssertFalse(serialized.contains(sentinel))
    }
    XCTAssertFalse(
      serialized.contains("0.146.0"),
      "Even safe report details stay out of entries; the code is enough."
    )
  }

  func testMethodAllowlistCoversExactlyTheConsumedProtocolSurface() {
    let expected: Set<String> = [
      "turn/started", "turn/completed", "thread/status/changed",
      "item/agentMessage/delta", "turn/plan/updated", "turn/diff/updated",
      "item/started", "item/completed", "serverRequest/resolved",
      "thread/archived", "item/commandExecution/requestApproval",
      "item/fileChange/requestApproval", "item/permissions/requestApproval",
    ]
    XCTAssertEqual(Set(KnownCodexMethod.allCases.map(\.rawValue)), expected)
  }

  private func serializeEntries(_ events: [BridgeLogEvent]) throws -> String {
    let sink = CapturingLogSink()
    let logger = RedactedLogger(sink: sink)
    for event in events {
      logger.log(event, at: Date(timeIntervalSince1970: 1_754_000_000))
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(sink.entries())
    return String(decoding: data, as: UTF8.self)
  }
}

private final class CapturingLogSink: RedactedLogSink, @unchecked Sendable {
  private let lock = NSLock()
  private var captured: [RedactedLogEntry] = []

  func write(_ entry: RedactedLogEntry) {
    lock.lock()
    captured.append(entry)
    lock.unlock()
  }

  func entries() -> [RedactedLogEntry] {
    lock.lock()
    defer { lock.unlock() }
    return captured
  }
}
