import CompanionProtocol
import CryptoKit
import Foundation

public enum CommandLifecycleState: String, Codable, Equatable, Sendable {
  case submitting
  case submitted
  case succeeded
  case failed
  case declined
  case outcomeUnknown

  public var isTerminal: Bool {
    switch self {
    case .succeeded, .failed, .declined, .outcomeUnknown:
      true
    case .submitting, .submitted:
      false
    }
  }
}

public enum CommandResultCode: String, Codable, Equatable, Sendable {
  case completed
  case rejectedByPolicy
  case rejectedByCodex
  case invalidRequest
  case codexUnavailable
  case bridgeRestartedBeforeOutcome
  case confirmationTimedOut
}

public struct CommandLedgerRecord: Codable, Equatable, Sendable {
  public let commandID: UUID
  public let deviceID: UUID
  public let commandKind: CompanionCommandKind
  public let requestDigest: String
  public private(set) var state: CommandLifecycleState
  public private(set) var threadID: String?
  public private(set) var turnID: String?
  public private(set) var requestID: String?
  public private(set) var resultCode: CommandResultCode?
  public let createdAt: Date
  public private(set) var updatedAt: Date

  init(
    commandID: UUID,
    deviceID: UUID,
    commandKind: CompanionCommandKind,
    requestDigest: String,
    state: CommandLifecycleState,
    threadID: String? = nil,
    turnID: String? = nil,
    requestID: String? = nil,
    resultCode: CommandResultCode? = nil,
    createdAt: Date,
    updatedAt: Date
  ) {
    self.commandID = commandID
    self.deviceID = deviceID
    self.commandKind = commandKind
    self.requestDigest = requestDigest
    self.state = state
    self.threadID = threadID
    self.turnID = turnID
    self.requestID = requestID
    self.resultCode = resultCode
    self.createdAt = createdAt
    self.updatedAt = updatedAt
  }

  mutating func markSubmitted(
    threadID: String?,
    turnID: String?,
    requestID: String?,
    at date: Date
  ) {
    state = .submitted
    self.threadID = threadID
    self.turnID = turnID
    self.requestID = requestID
    updatedAt = date
  }

  mutating func finish(
    state: CommandLifecycleState,
    resultCode: CommandResultCode,
    at date: Date
  ) {
    self.state = state
    self.resultCode = resultCode
    updatedAt = date
  }

  mutating func markOutcomeUnknown(
    resultCode: CommandResultCode = .bridgeRestartedBeforeOutcome,
    at date: Date
  ) {
    state = .outcomeUnknown
    self.resultCode = resultCode
    updatedAt = date
  }
}

public enum CommandRegistration: Equatable, Sendable {
  case accepted(CommandLedgerRecord)
  case replay(CommandLedgerRecord)
}

public enum CommandLedgerError: Error, Equatable, Sendable {
  case commandIDCollision
  case missingCommand
  case invalidTransition
  case invalidTerminalState
}

/// The ledger operations command executors depend on, satisfied by both the
/// in-memory prototype and the encrypted persistent ledger.
public protocol CommandLedgering: Sendable {
  func register(
    deviceID: UUID,
    command: ClientCommand,
    at date: Date
  ) async throws -> CommandRegistration

  func markSubmitted(
    commandID: UUID,
    threadID: String?,
    turnID: String?,
    requestID: String?,
    at date: Date
  ) async throws

  func finish(
    commandID: UUID,
    state: CommandLifecycleState,
    resultCode: CommandResultCode,
    at date: Date
  ) async throws

  func markOutcomeUnknown(
    commandID: UUID,
    resultCode: CommandResultCode,
    at date: Date
  ) async throws

  func record(commandID: UUID) async -> CommandLedgerRecord?
}

public actor InMemoryCommandLedger {
  private var records: [UUID: CommandLedgerRecord] = [:]

  public init() {}

  public func register(
    deviceID: UUID,
    command: ClientCommand,
    at date: Date = Date()
  ) throws -> CommandRegistration {
    let digest = try CommandFingerprint.digest(command)
    if let existing = records[command.commandID] {
      guard existing.deviceID == deviceID, existing.requestDigest == digest else {
        throw CommandLedgerError.commandIDCollision
      }
      return .replay(existing)
    }

    let record = CommandLedgerRecord(
      commandID: command.commandID,
      deviceID: deviceID,
      commandKind: command.body.kind,
      requestDigest: digest,
      state: .submitting,
      createdAt: date,
      updatedAt: date
    )
    records[command.commandID] = record
    return .accepted(record)
  }

  public func markSubmitted(
    commandID: UUID,
    threadID: String? = nil,
    turnID: String? = nil,
    requestID: String? = nil,
    at date: Date = Date()
  ) throws {
    guard var record = records[commandID] else { throw CommandLedgerError.missingCommand }
    guard record.state == .submitting else { throw CommandLedgerError.invalidTransition }
    record.markSubmitted(
      threadID: threadID,
      turnID: turnID,
      requestID: requestID,
      at: date
    )
    records[commandID] = record
  }

  public func finish(
    commandID: UUID,
    state: CommandLifecycleState,
    resultCode: CommandResultCode,
    at date: Date = Date()
  ) throws {
    guard [.succeeded, .failed, .declined].contains(state) else {
      throw CommandLedgerError.invalidTerminalState
    }
    guard var record = records[commandID] else { throw CommandLedgerError.missingCommand }
    guard record.state == .submitting || record.state == .submitted else {
      throw CommandLedgerError.invalidTransition
    }
    record.finish(state: state, resultCode: resultCode, at: date)
    records[commandID] = record
  }

  public func markInFlightOutcomesUnknown(at date: Date = Date()) {
    for commandID in Array(records.keys) {
      guard var record = records[commandID], !record.state.isTerminal else { continue }
      record.markOutcomeUnknown(at: date)
      records[commandID] = record
    }
  }

  public func markOutcomeUnknown(
    commandID: UUID,
    resultCode: CommandResultCode = .bridgeRestartedBeforeOutcome,
    at date: Date = Date()
  ) throws {
    guard var record = records[commandID] else { throw CommandLedgerError.missingCommand }
    guard !record.state.isTerminal else { throw CommandLedgerError.invalidTransition }
    record.markOutcomeUnknown(resultCode: resultCode, at: date)
    records[commandID] = record
  }

  public func record(commandID: UUID) -> CommandLedgerRecord? {
    records[commandID]
  }
}

extension InMemoryCommandLedger: CommandLedgering {}

public enum CommandFingerprint {
  public static func digest(_ command: ClientCommand) throws -> String {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .millisecondsSince1970
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let hash = SHA256.hash(data: try encoder.encode(command))
    return hash.map { String(format: "%02x", $0) }.joined()
  }
}
