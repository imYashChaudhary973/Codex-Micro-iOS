public struct ThreadRuntimeSnapshot: Equatable, Sendable {
  public let threadID: String
  public private(set) var status: String
  public private(set) var activeTurnID: String?
  public private(set) var lastTurnID: String?
  public private(set) var lastTurnStatus: String?

  public init(thread: JSONValue) throws {
    guard let threadID = thread["id"].string else {
      throw ThreadRuntimeSnapshotError.missingThreadID
    }

    self.threadID = threadID
    status = Self.status(from: thread["status"])

    let latestTurn = thread["turns"].array?.last
    let latestTurnID = latestTurn?["id"].string
    let latestTurnStatus = latestTurn?["status"].string
    lastTurnID = latestTurnID
    lastTurnStatus = latestTurnStatus
    activeTurnID = latestTurnStatus == "inProgress" ? latestTurnID : nil
  }

  public mutating func apply(_ event: AppServerEvent, routedTo routedThreadID: String) {
    guard routedThreadID == threadID else { return }

    switch event {
    case .notification(let method, let params):
      switch method {
      case "thread/status/changed":
        guard params["threadId"].string == threadID else { return }
        status = Self.status(from: params["status"])
      case "turn/started":
        guard let turnID = params["turn"]["id"].string else { return }
        activeTurnID = turnID
        lastTurnID = turnID
        lastTurnStatus = params["turn"]["status"].string ?? "inProgress"
      case "turn/completed":
        guard let turnID = params["turn"]["id"].string else { return }
        if activeTurnID == turnID {
          activeTurnID = nil
        }
        lastTurnID = turnID
        lastTurnStatus = params["turn"]["status"].string ?? "unknown"
      default:
        break
      }
    case .serverRequest, .protocolWarning:
      break
    }
  }

  private static func status(from value: JSONValue) -> String {
    value.string
      ?? value["type"].string
      ?? value.object?.keys.sorted().first
      ?? "unknown"
  }
}

public enum ThreadRuntimeSnapshotError: Error, Equatable, Sendable {
  case missingThreadID
}
