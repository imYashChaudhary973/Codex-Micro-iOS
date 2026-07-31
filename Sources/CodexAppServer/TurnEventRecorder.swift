import Foundation

public struct TurnEventSummary: Equatable, Sendable {
  public let turnID: String
  public let finalStatus: String
  public let notificationCounts: [String: Int]
  public let serverRequestCounts: [String: Int]
  public let agentMessageCharacterCount: Int

  public init(
    turnID: String,
    finalStatus: String,
    notificationCounts: [String: Int],
    serverRequestCounts: [String: Int],
    agentMessageCharacterCount: Int
  ) {
    self.turnID = turnID
    self.finalStatus = finalStatus
    self.notificationCounts = notificationCounts
    self.serverRequestCounts = serverRequestCounts
    self.agentMessageCharacterCount = agentMessageCharacterCount
  }
}

public enum TurnEventRecorderError: Error, LocalizedError, Equatable, Sendable {
  case streamEnded(turnID: String)
  case timedOut(turnID: String)
  case unexpectedServerRequest(id: Int64, method: String)
  case protocolWarning(String)

  public var errorDescription: String? {
    switch self {
    case .streamEnded(let turnID):
      "Codex event stream ended before turn \(turnID) completed."
    case .timedOut(let turnID):
      "Codex turn \(turnID) did not complete before the event timeout."
    case .unexpectedServerRequest(_, let method):
      "Codex requested \(method); the probe interrupted the turn without answering it."
    case .protocolWarning(let warning):
      "Codex protocol warning: \(warning)"
    }
  }
}

public enum TurnEventRecorder {
  public typealias ServerRequestHandler =
    @Sendable (Int64, String, JSONValue) async throws -> Void

  public static func collect(
    events: AsyncStream<AppServerEvent>,
    turnID: String,
    timeout: Duration = .seconds(90),
    onTurnStarted: (@Sendable () async throws -> Void)? = nil,
    onServerRequest: ServerRequestHandler? = nil
  ) async throws -> TurnEventSummary {
    try await withThrowingTaskGroup(of: TurnEventSummary.self) { group in
      group.addTask {
        try await collectUntilComplete(
          events: events,
          turnID: turnID,
          onTurnStarted: onTurnStarted,
          onServerRequest: onServerRequest
        )
      }
      group.addTask {
        try await Task.sleep(for: timeout)
        throw TurnEventRecorderError.timedOut(turnID: turnID)
      }

      guard let result = try await group.next() else {
        throw TurnEventRecorderError.streamEnded(turnID: turnID)
      }
      group.cancelAll()
      return result
    }
  }

  public static func waitUntilStarted(
    events: AsyncStream<AppServerEvent>,
    turnID: String,
    timeout: Duration = .seconds(30)
  ) async throws {
    try await withThrowingTaskGroup(of: Bool.self) { group in
      group.addTask {
        for await event in events {
          switch event {
          case .notification(let method, let params)
          where method == "turn/started" && params["turn"]["id"].string == turnID:
            return true
          case .serverRequest(let id, let method, _):
            throw TurnEventRecorderError.unexpectedServerRequest(id: id, method: method)
          case .protocolWarning(let warning):
            throw TurnEventRecorderError.protocolWarning(warning)
          default:
            continue
          }
        }
        throw TurnEventRecorderError.streamEnded(turnID: turnID)
      }
      group.addTask {
        try await Task.sleep(for: timeout)
        throw TurnEventRecorderError.timedOut(turnID: turnID)
      }

      _ = try await group.next()
      group.cancelAll()
    }
  }

  private static func collectUntilComplete(
    events: AsyncStream<AppServerEvent>,
    turnID: String,
    onTurnStarted: (@Sendable () async throws -> Void)?,
    onServerRequest: ServerRequestHandler?
  ) async throws -> TurnEventSummary {
    var notificationCounts: [String: Int] = [:]
    var serverRequestCounts: [String: Int] = [:]
    var agentMessageCharacterCount = 0
    var handledTurnStart = false

    for await event in events {
      switch event {
      case .notification(let method, let params):
        notificationCounts[method, default: 0] += 1

        if method == "turn/started", params["turn"]["id"].string == turnID,
          !handledTurnStart
        {
          handledTurnStart = true
          try await onTurnStarted?()
        }

        if method == "item/agentMessage/delta", params["turnId"].string == turnID {
          agentMessageCharacterCount += params["delta"].string?.count ?? 0
        }

        if method == "turn/completed", params["turn"]["id"].string == turnID {
          return TurnEventSummary(
            turnID: turnID,
            finalStatus: status(from: params["turn"]["status"]),
            notificationCounts: notificationCounts,
            serverRequestCounts: serverRequestCounts,
            agentMessageCharacterCount: agentMessageCharacterCount
          )
        }
      case .serverRequest(let id, let method, let params):
        serverRequestCounts[method, default: 0] += 1
        guard let onServerRequest else {
          throw TurnEventRecorderError.unexpectedServerRequest(id: id, method: method)
        }
        try await onServerRequest(id, method, params)
      case .protocolWarning(let warning):
        throw TurnEventRecorderError.protocolWarning(warning)
      }
    }

    throw TurnEventRecorderError.streamEnded(turnID: turnID)
  }

  private static func status(from value: JSONValue) -> String {
    value.string
      ?? value["type"].string
      ?? value.object?.keys.sorted().first
      ?? "unknown"
  }
}
