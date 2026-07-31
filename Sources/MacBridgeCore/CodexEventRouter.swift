import CodexAppServer
import CompanionProtocol
import Foundation

public struct RoutedAppServerEvent: Equatable, Sendable {
  public let threadID: String
  public let turnID: String?
  public let event: AppServerEvent

  public init(threadID: String, turnID: String?, event: AppServerEvent) {
    self.threadID = threadID
    self.turnID = turnID
    self.event = event
  }
}

public enum CodexEventRoutingError: Error, Equatable, Sendable {
  case missingThreadID
  case missingTurnID
  case unknownTurn(String)
  case conflictingTurnRoute(turnID: String)
  case protocolWarning
}

public struct CodexEventRouter: Sendable {
  private var threadByTurnID: [String: String] = [:]

  public init() {}

  public mutating func registerThreadSnapshot(_ thread: JSONValue) throws {
    guard let threadID = validID(thread["id"].string) else {
      throw CodexEventRoutingError.missingThreadID
    }
    for turn in thread["turns"].array ?? [] {
      guard let turnID = validID(turn["id"].string) else {
        throw CodexEventRoutingError.missingTurnID
      }
      try bind(turnID: turnID, to: threadID)
    }
  }

  @discardableResult
  public mutating func registerTurnStartResponse(
    threadID: String,
    response: JSONValue
  ) throws -> String {
    guard let validThreadID = validID(threadID) else {
      throw CodexEventRoutingError.missingThreadID
    }
    guard let turnID = validID(response["turn"]["id"].string) else {
      throw CodexEventRoutingError.missingTurnID
    }
    try bind(turnID: turnID, to: validThreadID)
    return turnID
  }

  public mutating func route(_ event: AppServerEvent) throws -> RoutedAppServerEvent? {
    switch event {
    case .protocolWarning:
      throw CodexEventRoutingError.protocolWarning
    case .serverRequest(_, _, let params):
      return try routeWithExplicitContext(event: event, params: params)
    case .notification(let method, let params):
      if let threadID = validID(params["threadId"].string) {
        let turnID = validID(params["turnId"].string)
        if let turnID { try bind(turnID: turnID, to: threadID) }
        return RoutedAppServerEvent(threadID: threadID, turnID: turnID, event: event)
      }

      guard method == "turn/started" || method == "turn/completed" else {
        return nil
      }
      guard let turnID = validID(params["turn"]["id"].string) else {
        throw CodexEventRoutingError.missingTurnID
      }
      guard let threadID = threadByTurnID[turnID] else {
        throw CodexEventRoutingError.unknownTurn(turnID)
      }
      return RoutedAppServerEvent(threadID: threadID, turnID: turnID, event: event)
    }
  }

  public mutating func forgetThread(_ threadID: String) {
    threadByTurnID = threadByTurnID.filter { $0.value != threadID }
  }

  private mutating func routeWithExplicitContext(
    event: AppServerEvent,
    params: JSONValue
  ) throws -> RoutedAppServerEvent {
    guard let threadID = validID(params["threadId"].string) else {
      throw CodexEventRoutingError.missingThreadID
    }
    let turnID = validID(params["turnId"].string)
    if let turnID { try bind(turnID: turnID, to: threadID) }
    return RoutedAppServerEvent(threadID: threadID, turnID: turnID, event: event)
  }

  private mutating func bind(turnID: String, to threadID: String) throws {
    if let existing = threadByTurnID[turnID], existing != threadID {
      throw CodexEventRoutingError.conflictingTurnRoute(turnID: turnID)
    }
    threadByTurnID[turnID] = threadID
  }

  private func validID(_ value: String?) -> String? {
    guard let value, !value.isEmpty, value == value.trimmingCharacters(in: .whitespacesAndNewlines)
    else { return nil }
    return value
  }
}

public enum CodexDomainStoreResult: Equatable, Sendable {
  case updated(threadID: String)
  case ignored
  case snapshotRequired(threadID: String)
}

public actor CodexDomainStore {
  private var router = CodexEventRouter()
  private var threads: [String: ThreadRuntimeSnapshot] = [:]
  private var approvals = PendingApprovalRegistry()

  public init() {}

  public func replaceThread(with thread: JSONValue) throws {
    let snapshot = try ThreadRuntimeSnapshot(thread: thread)
    try router.registerThreadSnapshot(thread)
    threads[snapshot.threadID] = snapshot
  }

  @discardableResult
  public func registerTurnStartResponse(
    threadID: String,
    response: JSONValue
  ) throws -> String {
    try router.registerTurnStartResponse(threadID: threadID, response: response)
  }

  public func apply(
    _ event: AppServerEvent,
    now: Date = Date()
  ) throws -> CodexDomainStoreResult {
    guard let routed = try router.route(event) else { return .ignored }
    guard var snapshot = threads[routed.threadID] else {
      return .snapshotRequired(threadID: routed.threadID)
    }
    switch routed.event {
    case .serverRequest(let rpcID, let method, let params):
      if Self.isApprovalRequest(method) {
        _ = try approvals.ingest(rpcID: rpcID, method: method, params: params, now: now)
      }
    case .notification(let method, let params) where method == "serverRequest/resolved":
      approvals.handleResolvedNotification(params)
    default:
      break
    }
    snapshot.apply(routed.event, routedTo: routed.threadID)
    threads[routed.threadID] = snapshot
    return .updated(threadID: routed.threadID)
  }

  public func snapshot(threadID: String) -> ThreadRuntimeSnapshot? {
    threads[threadID]
  }

  public func allSnapshots() -> [ThreadRuntimeSnapshot] {
    threads.values.sorted { $0.threadID < $1.threadID }
  }

  public func makeCompanionSnapshot(
    latestSequence: UInt64,
    generatedAt: Date = Date(),
    now: Date = Date()
  ) -> CompanionStateSnapshot {
    CompanionStateSnapshot(
      generatedAt: generatedAt,
      latestSequence: latestSequence,
      threads: threads.values
        .map(Self.normalize)
        .sorted { $0.threadID < $1.threadID },
      pendingApprovals: approvals.summaries(now: now)
    )
  }

  public func prepareApprovalResolution(
    requestID: String,
    requestDigest: String,
    decision: CompanionApprovalDecision,
    userPresence: ApprovalUserPresenceProof? = nil,
    now: Date = Date()
  ) throws -> PreparedApprovalResolution {
    try approvals.prepareResolution(
      requestID: requestID,
      requestDigest: requestDigest,
      decision: decision,
      userPresence: userPresence,
      now: now
    )
  }

  public func markApprovalResolved(requestID: String) {
    approvals.markResolved(requestID: requestID)
  }

  public func markApprovalOutcomeUnknown(requestID: String) throws {
    try approvals.markOutcomeUnknown(requestID: requestID)
  }

  public func removeThread(threadID: String) {
    threads.removeValue(forKey: threadID)
    router.forgetThread(threadID)
  }

  private static func normalize(_ snapshot: ThreadRuntimeSnapshot) -> CompanionThreadState {
    CompanionThreadState(
      threadID: snapshot.threadID,
      status: normalizeThreadStatus(snapshot.status),
      activeTurnID: snapshot.activeTurnID,
      lastTurnID: snapshot.lastTurnID,
      lastTurnStatus: snapshot.lastTurnStatus.map(normalizeTurnStatus)
    )
  }

  private static func normalizeThreadStatus(_ status: String) -> CompanionThreadStatus {
    switch status {
    case "idle", "notLoaded":
      .idle
    case "active", "running":
      .active
    case "error", "failed":
      .error
    default:
      .unknown
    }
  }

  private static func normalizeTurnStatus(_ status: String) -> CompanionTurnStatus {
    CompanionTurnStatus(rawValue: status) ?? .unknown
  }

  private static func isApprovalRequest(_ method: String) -> Bool {
    switch method {
    case "item/commandExecution/requestApproval", "item/fileChange/requestApproval",
      "item/permissions/requestApproval":
      true
    default:
      false
    }
  }
}
