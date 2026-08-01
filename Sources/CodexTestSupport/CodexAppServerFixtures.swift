import CodexAppServer
import Foundation

/// Canonical sanitized JSON-RPC payloads for every notification and approval
/// request type the bridge consumes, plus adversarial shapes for fail-closed
/// tests. Content parameters default to placeholder strings and exist so leak
/// tests can inject sentinels; fixtures never carry real user data.
public enum CodexAppServerFixtures {
  // MARK: - Handshake

  public static func initializeResult() -> JSONValue {
    .object([
      "codexHome": .string("/tmp/codex-fixture"),
      "platformFamily": .string("unix"),
      "platformOs": .string("macos"),
      "userAgent": .string("codex-fake-app-server"),
    ])
  }

  // MARK: - Threads and turns

  public static func turn(id: String, status: String = "completed") -> JSONValue {
    .object(["id": .string(id), "status": .string(status)])
  }

  public static func thread(
    id: String,
    status: String = "idle",
    turns: [JSONValue] = []
  ) -> JSONValue {
    .object([
      "id": .string(id),
      "status": .object(["type": .string(status)]),
      "turns": .array(turns),
    ])
  }

  public static func threadReadResult(_ thread: JSONValue) -> JSONValue {
    .object(["thread": thread])
  }

  public static func turnStartResult(turnID: String) -> JSONValue {
    .object([
      "turn": .object([
        "id": .string(turnID),
        "status": .string("inProgress"),
      ])
    ])
  }

  // MARK: - Consumed notifications

  public static func notification(method: String, params: JSONValue) -> JSONValue {
    .object(["method": .string(method), "params": params])
  }

  public static func turnStarted(turnID: String, status: String = "inProgress") -> JSONValue {
    notification(
      method: "turn/started",
      params: .object([
        "turn": .object(["id": .string(turnID), "status": .string(status)])
      ]))
  }

  public static func turnCompleted(turnID: String, status: String = "completed") -> JSONValue {
    notification(
      method: "turn/completed",
      params: .object([
        "turn": .object(["id": .string(turnID), "status": .string(status)])
      ]))
  }

  public static func threadStatusChanged(threadID: String, status: String) -> JSONValue {
    notification(
      method: "thread/status/changed",
      params: .object([
        "threadId": .string(threadID),
        "status": .object(["type": .string(status)]),
      ]))
  }

  public static func agentMessageDelta(
    threadID: String,
    turnID: String,
    delta: String = "fixture-delta"
  ) -> JSONValue {
    notification(
      method: "item/agentMessage/delta",
      params: .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
        "delta": .string(delta),
      ]))
  }

  public static func planUpdated(
    threadID: String,
    turnID: String,
    explanation: String = "fixture-plan"
  ) -> JSONValue {
    notification(
      method: "turn/plan/updated",
      params: .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
        "explanation": .string(explanation),
      ]))
  }

  public static func diffUpdated(
    threadID: String,
    turnID: String,
    diff: String = "fixture-diff"
  ) -> JSONValue {
    notification(
      method: "turn/diff/updated",
      params: .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
        "diff": .string(diff),
      ]))
  }

  public static func commandItemStarted(
    threadID: String,
    turnID: String,
    itemID: String = "item-fixture",
    command: String = "fixture-command"
  ) -> JSONValue {
    notification(
      method: "item/started",
      params: .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
        "item": .object([
          "id": .string(itemID),
          "type": .string("commandExecution"),
          "command": .string(command),
        ]),
      ]))
  }

  public static func commandItemCompleted(
    threadID: String,
    turnID: String,
    itemID: String = "item-fixture"
  ) -> JSONValue {
    notification(
      method: "item/completed",
      params: .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
        "item": .object([
          "id": .string(itemID),
          "type": .string("commandExecution"),
        ]),
      ]))
  }

  public static func serverRequestResolved(
    requestID: Int64,
    threadID: String,
    turnID: String
  ) -> JSONValue {
    notification(
      method: "serverRequest/resolved",
      params: .object([
        "requestId": .integer(requestID),
        "threadId": .string(threadID),
        "turnId": .string(turnID),
      ]))
  }

  public static func threadArchived(threadID: String) -> JSONValue {
    notification(
      method: "thread/archived",
      params: .object(["threadId": .string(threadID)]))
  }

  // MARK: - Approval server requests (every consumed kind)

  public static func commandApprovalRequest(
    rpcID: Int64,
    threadID: String,
    turnID: String,
    itemID: String = "item-fixture",
    startedAt: Date
  ) -> JSONValue {
    approvalRequest(
      rpcID: rpcID,
      method: "item/commandExecution/requestApproval",
      threadID: threadID,
      turnID: turnID,
      itemID: itemID,
      startedAt: startedAt,
      extraParams: [:])
  }

  public static func networkApprovalRequest(
    rpcID: Int64,
    threadID: String,
    turnID: String,
    itemID: String = "item-fixture",
    startedAt: Date
  ) -> JSONValue {
    approvalRequest(
      rpcID: rpcID,
      method: "item/commandExecution/requestApproval",
      threadID: threadID,
      turnID: turnID,
      itemID: itemID,
      startedAt: startedAt,
      extraParams: [
        "networkApprovalContext": .object(["destination": .string("fixture-host")])
      ])
  }

  public static func fileChangeApprovalRequest(
    rpcID: Int64,
    threadID: String,
    turnID: String,
    itemID: String = "item-fixture",
    startedAt: Date
  ) -> JSONValue {
    approvalRequest(
      rpcID: rpcID,
      method: "item/fileChange/requestApproval",
      threadID: threadID,
      turnID: turnID,
      itemID: itemID,
      startedAt: startedAt,
      extraParams: [:])
  }

  public static func permissionsApprovalRequest(
    rpcID: Int64,
    threadID: String,
    turnID: String,
    itemID: String = "item-fixture",
    startedAt: Date,
    permissions: JSONValue = .object(["network": .bool(true)])
  ) -> JSONValue {
    approvalRequest(
      rpcID: rpcID,
      method: "item/permissions/requestApproval",
      threadID: threadID,
      turnID: turnID,
      itemID: itemID,
      startedAt: startedAt,
      extraParams: ["permissions": permissions])
  }

  /// An approval request missing the fields the registry requires; the
  /// bridge must reject it rather than guess.
  public static func invalidApprovalRequest(
    rpcID: Int64,
    threadID: String,
    turnID: String
  ) -> JSONValue {
    .object([
      "id": .integer(rpcID),
      "method": .string("item/commandExecution/requestApproval"),
      "params": .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
      ]),
    ])
  }

  // MARK: - Adversarial shapes

  public static func unknownNotification(threadID: String? = nil) -> JSONValue {
    var params: [String: JSONValue] = ["detail": .string("fixture-unknown")]
    if let threadID {
      params["threadId"] = .string(threadID)
    }
    return notification(method: "future/experimentalEvent", params: .object(params))
  }

  public static func unknownServerRequest(
    rpcID: Int64,
    threadID: String,
    turnID: String
  ) -> JSONValue {
    .object([
      "id": .integer(rpcID),
      "method": .string("future/requestSomething"),
      "params": .object([
        "threadId": .string(threadID),
        "turnId": .string(turnID),
      ]),
    ])
  }

  public static var malformedLine: Data {
    Data("{ this is not json".utf8)
  }

  public static func messageWithoutMethod() -> JSONValue {
    .object(["params": .object(["detail": .string("fixture-no-method")])])
  }

  public static func responseWithUnknownRPCID(_ rpcID: Int64) -> JSONValue {
    .object(["id": .integer(rpcID), "result": .object([:])])
  }

  // MARK: - Private

  private static func approvalRequest(
    rpcID: Int64,
    method: String,
    threadID: String,
    turnID: String,
    itemID: String,
    startedAt: Date,
    extraParams: [String: JSONValue]
  ) -> JSONValue {
    var params: [String: JSONValue] = [
      "threadId": .string(threadID),
      "turnId": .string(turnID),
      "itemId": .string(itemID),
      "startedAtMs": .integer(Int64(startedAt.timeIntervalSince1970 * 1_000)),
    ]
    for (key, value) in extraParams {
      params[key] = value
    }
    return .object([
      "id": .integer(rpcID),
      "method": .string(method),
      "params": .object(params),
    ])
  }
}
