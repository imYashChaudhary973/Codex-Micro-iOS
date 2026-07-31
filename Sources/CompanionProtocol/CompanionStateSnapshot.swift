import Foundation

public enum CompanionThreadStatus: String, Codable, Equatable, Sendable {
  case idle
  case active
  case error
  case unknown
}

public enum CompanionTurnStatus: String, Codable, Equatable, Sendable {
  case inProgress
  case completed
  case interrupted
  case failed
  case unknown
}

public struct CompanionThreadState: Codable, Equatable, Sendable {
  public let threadID: String
  public let status: CompanionThreadStatus
  public let activeTurnID: String?
  public let lastTurnID: String?
  public let lastTurnStatus: CompanionTurnStatus?

  public init(
    threadID: String,
    status: CompanionThreadStatus,
    activeTurnID: String?,
    lastTurnID: String?,
    lastTurnStatus: CompanionTurnStatus?
  ) {
    self.threadID = threadID
    self.status = status
    self.activeTurnID = activeTurnID
    self.lastTurnID = lastTurnID
    self.lastTurnStatus = lastTurnStatus
  }
}

public struct CompanionStateSnapshot: Codable, Equatable, Sendable {
  public let protocolVersion: ProtocolVersion
  public let generatedAt: Date
  public let latestSequence: UInt64
  public let threads: [CompanionThreadState]
  public let pendingApprovals: [CompanionPendingApproval]

  public init(
    protocolVersion: ProtocolVersion = .current,
    generatedAt: Date,
    latestSequence: UInt64,
    threads: [CompanionThreadState],
    pendingApprovals: [CompanionPendingApproval] = []
  ) {
    self.protocolVersion = protocolVersion
    self.generatedAt = generatedAt
    self.latestSequence = latestSequence
    self.threads = threads
    self.pendingApprovals = pendingApprovals
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    protocolVersion = try container.decode(ProtocolVersion.self, forKey: .protocolVersion)
    generatedAt = try container.decode(Date.self, forKey: .generatedAt)
    latestSequence = try container.decode(UInt64.self, forKey: .latestSequence)
    threads = try container.decode([CompanionThreadState].self, forKey: .threads)
    pendingApprovals =
      try container.decodeIfPresent([CompanionPendingApproval].self, forKey: .pendingApprovals)
      ?? []
  }

  private enum CodingKeys: String, CodingKey {
    case protocolVersion
    case generatedAt
    case latestSequence
    case threads
    case pendingApprovals
  }
}
