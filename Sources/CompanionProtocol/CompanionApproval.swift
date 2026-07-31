import Foundation

public enum CompanionApprovalKind: String, Codable, Equatable, Sendable {
  case command
  case fileChange
  case network
  case permissions
}

public enum CompanionApprovalStatus: String, Codable, Equatable, Sendable {
  case pending
  case resolving
  case outcomeUnknown
}

public struct CompanionPendingApproval: Codable, Equatable, Sendable {
  public let requestID: String
  public let threadID: String
  public let turnID: String
  public let itemID: String
  public let kind: CompanionApprovalKind
  public let availableDecisions: [CompanionApprovalDecision]
  public let requestDigest: String
  public let createdAt: Date
  public let expiresAt: Date
  public let status: CompanionApprovalStatus

  public init(
    requestID: String,
    threadID: String,
    turnID: String,
    itemID: String,
    kind: CompanionApprovalKind,
    availableDecisions: [CompanionApprovalDecision],
    requestDigest: String,
    createdAt: Date,
    expiresAt: Date,
    status: CompanionApprovalStatus
  ) {
    self.requestID = requestID
    self.threadID = threadID
    self.turnID = turnID
    self.itemID = itemID
    self.kind = kind
    self.availableDecisions = availableDecisions
    self.requestDigest = requestDigest
    self.createdAt = createdAt
    self.expiresAt = expiresAt
    self.status = status
  }

  public func withStatus(_ status: CompanionApprovalStatus) -> CompanionPendingApproval {
    CompanionPendingApproval(
      requestID: requestID,
      threadID: threadID,
      turnID: turnID,
      itemID: itemID,
      kind: kind,
      availableDecisions: availableDecisions,
      requestDigest: requestDigest,
      createdAt: createdAt,
      expiresAt: expiresAt,
      status: status
    )
  }
}
