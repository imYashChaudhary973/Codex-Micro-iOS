import CodexAppServer
import CompanionProtocol
import Foundation
import os

/// App-server methods the bridge is allowed to name in logs. Any method not
/// in this closed set is logged as unknown; the raw string never reaches a
/// log entry because a server-controlled method name could carry content.
public enum KnownCodexMethod: String, CaseIterable, Sendable {
  case turnStarted = "turn/started"
  case turnCompleted = "turn/completed"
  case threadStatusChanged = "thread/status/changed"
  case agentMessageDelta = "item/agentMessage/delta"
  case planUpdated = "turn/plan/updated"
  case diffUpdated = "turn/diff/updated"
  case itemStarted = "item/started"
  case itemCompleted = "item/completed"
  case serverRequestResolved = "serverRequest/resolved"
  case threadArchived = "thread/archived"
  case commandExecutionRequestApproval = "item/commandExecution/requestApproval"
  case fileChangeRequestApproval = "item/fileChange/requestApproval"
  case permissionsRequestApproval = "item/permissions/requestApproval"
}

public enum LedgerOperation: String, Sendable {
  case register
  case markSubmitted
  case finish
  case markOutcomeUnknown
  case purge
}

/// The closed vocabulary of everything the bridge can log. Associated values
/// are enums and integers only; free-form strings cannot enter an entry
/// without adding a new case here, which is exactly the review point.
public enum BridgeLogEvent: Equatable, Sendable {
  case runtimeStateChanged(CodexRuntimeState)
  case recoveryStarted(attempt: Int)
  case recoveryFailed(attempt: Int)
  case recoveryRebuilt(rebuiltThreadCount: Int, droppedThreadCount: Int)
  case appServerNotification(KnownCodexMethod?)
  case appServerRequest(KnownCodexMethod?)
  case protocolWarning
  case approvalIngested(kind: CompanionApprovalKind)
  case approvalRejected(reason: PendingApprovalError)
  case approvalResponseSent(decision: CompanionApprovalDecision)
  case approvalConfirmed
  case approvalOutcomeUnknown
  case commandRegistered(kind: CompanionCommandKind)
  case commandReplayed(kind: CompanionCommandKind)
  case commandFinished(state: CommandLifecycleState, resultCode: CommandResultCode)
  case ledgerOperationFailed(operation: LedgerOperation)
}

public enum BridgeLogLevel: String, Codable, Equatable, Sendable {
  case debug
  case info
  case warning
  case error
}

/// One serialized log line. Every string field is derived from compile-time
/// constants; numeric context travels in `counts`.
public struct RedactedLogEntry: Codable, Equatable, Sendable {
  public let timestamp: Date
  public let level: BridgeLogLevel
  public let code: String
  public let counts: [String: Int]

  public init(timestamp: Date, level: BridgeLogLevel, code: String, counts: [String: Int]) {
    self.timestamp = timestamp
    self.level = level
    self.code = code
    self.counts = counts
  }
}

public protocol RedactedLogSink: Sendable {
  func write(_ entry: RedactedLogEntry)
}

/// Production sink writing to unified logging. Entry contents are safe by
/// construction, so the public privacy level is correct here.
public struct OSLogSink: RedactedLogSink {
  private let logger: Logger

  public init(subsystem: String = "com.codexmicro.bridge", category: String = "bridge") {
    logger = Logger(subsystem: subsystem, category: category)
  }

  public func write(_ entry: RedactedLogEntry) {
    let counts = entry.counts.sorted { $0.key < $1.key }
      .map { "\($0.key)=\($0.value)" }
      .joined(separator: " ")
    switch entry.level {
    case .debug:
      logger.debug("\(entry.code, privacy: .public) \(counts, privacy: .public)")
    case .info:
      logger.info("\(entry.code, privacy: .public) \(counts, privacy: .public)")
    case .warning:
      logger.warning("\(entry.code, privacy: .public) \(counts, privacy: .public)")
    case .error:
      logger.error("\(entry.code, privacy: .public) \(counts, privacy: .public)")
    }
  }
}

/// Translates bridge activity into content-free entries. Raw Codex payloads
/// never pass through: `describe` maps app-server events onto the closed
/// vocabulary, dropping methods that are not allowlisted and ignoring params
/// entirely.
public struct RedactedLogger: Sendable {
  private let sink: any RedactedLogSink

  public init(sink: any RedactedLogSink = OSLogSink()) {
    self.sink = sink
  }

  public func log(_ event: BridgeLogEvent, at date: Date = Date()) {
    sink.write(Self.entry(for: event, at: date))
  }

  /// Maps a raw app-server event onto the closed vocabulary. Params and
  /// warning text are intentionally discarded.
  public static func describe(_ event: AppServerEvent) -> BridgeLogEvent {
    switch event {
    case .notification(let method, _):
      .appServerNotification(KnownCodexMethod(rawValue: method))
    case .serverRequest(_, let method, _):
      .appServerRequest(KnownCodexMethod(rawValue: method))
    case .protocolWarning:
      .protocolWarning
    }
  }

  /// Maps a recovery event onto the closed vocabulary. Thread IDs are
  /// reduced to counts.
  public static func describe(_ event: CodexRecoveryEvent) -> BridgeLogEvent {
    switch event {
    case .runtimeState(let state):
      .runtimeStateChanged(state)
    case .recoveryStarted(let attempt):
      .recoveryStarted(attempt: attempt)
    case .recoveryFailed(let attempt):
      .recoveryFailed(attempt: attempt)
    case .rebuilt(let threadIDs, let droppedThreadIDs):
      .recoveryRebuilt(
        rebuiltThreadCount: threadIDs.count,
        droppedThreadCount: droppedThreadIDs.count
      )
    }
  }

  static func entry(for event: BridgeLogEvent, at date: Date) -> RedactedLogEntry {
    switch event {
    case .runtimeStateChanged(let state):
      RedactedLogEntry(
        timestamp: date,
        level: Self.level(for: state),
        code: "runtime.\(Self.code(for: state))",
        counts: [:]
      )
    case .recoveryStarted(let attempt):
      RedactedLogEntry(
        timestamp: date,
        level: .warning,
        code: "recovery.started",
        counts: ["attempt": attempt]
      )
    case .recoveryFailed(let attempt):
      RedactedLogEntry(
        timestamp: date,
        level: .error,
        code: "recovery.failed",
        counts: ["attempt": attempt]
      )
    case .recoveryRebuilt(let rebuiltThreadCount, let droppedThreadCount):
      RedactedLogEntry(
        timestamp: date,
        level: .info,
        code: "recovery.rebuilt",
        counts: ["rebuilt": rebuiltThreadCount, "dropped": droppedThreadCount]
      )
    case .appServerNotification(let method):
      RedactedLogEntry(
        timestamp: date,
        level: .debug,
        code: "event.notification.\(method?.rawValue ?? "unknown")",
        counts: [:]
      )
    case .appServerRequest(let method):
      RedactedLogEntry(
        timestamp: date,
        level: .info,
        code: "event.request.\(method?.rawValue ?? "unknown")",
        counts: [:]
      )
    case .protocolWarning:
      RedactedLogEntry(
        timestamp: date,
        level: .warning,
        code: "event.protocolWarning",
        counts: [:]
      )
    case .approvalIngested(let kind):
      RedactedLogEntry(
        timestamp: date,
        level: .info,
        code: "approval.ingested.\(kind.rawValue)",
        counts: [:]
      )
    case .approvalRejected(let reason):
      RedactedLogEntry(
        timestamp: date,
        level: .warning,
        code: "approval.rejected.\(Self.code(for: reason))",
        counts: [:]
      )
    case .approvalResponseSent(let decision):
      RedactedLogEntry(
        timestamp: date,
        level: .info,
        code: "approval.responseSent.\(decision.rawValue)",
        counts: [:]
      )
    case .approvalConfirmed:
      RedactedLogEntry(
        timestamp: date, level: .info, code: "approval.confirmed", counts: [:]
      )
    case .approvalOutcomeUnknown:
      RedactedLogEntry(
        timestamp: date, level: .error, code: "approval.outcomeUnknown", counts: [:]
      )
    case .commandRegistered(let kind):
      RedactedLogEntry(
        timestamp: date,
        level: .info,
        code: "command.registered.\(kind.rawValue)",
        counts: [:]
      )
    case .commandReplayed(let kind):
      RedactedLogEntry(
        timestamp: date,
        level: .info,
        code: "command.replayed.\(kind.rawValue)",
        counts: [:]
      )
    case .commandFinished(let state, let resultCode):
      RedactedLogEntry(
        timestamp: date,
        level: state == .succeeded ? .info : .warning,
        code: "command.finished.\(state.rawValue).\(resultCode.rawValue)",
        counts: [:]
      )
    case .ledgerOperationFailed(let operation):
      RedactedLogEntry(
        timestamp: date,
        level: .error,
        code: "ledger.operationFailed.\(operation.rawValue)",
        counts: [:]
      )
    }
  }

  private static func code(for state: CodexRuntimeState) -> String {
    switch state {
    case .stopped: "stopped"
    case .checkingCompatibility: "checkingCompatibility"
    case .unsupported(.supported): "unsupported.unexpected"
    case .unsupported(.unsupportedVersion): "unsupported.unsupportedVersion"
    case .unsupported(.schemaMismatch): "unsupported.schemaMismatch"
    case .starting: "starting"
    case .ready: "ready"
    case .degraded(.compatibilityCheckFailed): "degraded.compatibilityCheckFailed"
    case .degraded(.startupFailed): "degraded.startupFailed"
    case .degraded(.connectionClosed): "degraded.connectionClosed"
    }
  }

  private static func level(for state: CodexRuntimeState) -> BridgeLogLevel {
    switch state {
    case .stopped, .checkingCompatibility, .starting, .ready: .info
    case .unsupported, .degraded: .error
    }
  }

  private static func code(for reason: PendingApprovalError) -> String {
    switch reason {
    case .unsupportedRequest: "unsupportedRequest"
    case .invalidRequest: "invalidRequest"
    case .invalidTimestamp: "invalidTimestamp"
    case .expired: "expired"
    case .requestIDCollision: "requestIDCollision"
    case .missingRequest: "missingRequest"
    case .digestMismatch: "digestMismatch"
    case .notPending: "notPending"
    case .userPresenceRequired: "userPresenceRequired"
    case .invalidUserPresence: "invalidUserPresence"
    }
  }
}
