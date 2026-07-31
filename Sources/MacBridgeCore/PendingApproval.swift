import CodexAppServer
import CompanionProtocol
import Foundation
@preconcurrency import LocalAuthentication

public enum PendingApprovalError: Error, Equatable, Sendable {
  case unsupportedRequest
  case invalidRequest
  case invalidTimestamp
  case expired
  case requestIDCollision
  case missingRequest
  case digestMismatch
  case notPending
  case userPresenceRequired
  case invalidUserPresence
}

public struct ApprovalUserPresenceProof: Equatable, Sendable {
  fileprivate let requestDigest: String
  fileprivate let verifiedAt: Date
  fileprivate let expiresAt: Date

  static func verifiedForTesting(
    requestDigest: String,
    verifiedAt: Date,
    expiresAt: Date
  ) -> ApprovalUserPresenceProof {
    ApprovalUserPresenceProof(
      requestDigest: requestDigest,
      verifiedAt: verifiedAt,
      expiresAt: expiresAt
    )
  }
}

public enum ApprovalAuthenticationError: Error, Equatable, Sendable {
  case unavailable
  case failed
}

public struct LocalApprovalAuthenticator: Sendable {
  public init() {}

  public func authenticate(
    requestDigest: String,
    reason: String
  ) async throws -> ApprovalUserPresenceProof {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
      throw ApprovalAuthenticationError.unavailable
    }

    let accepted = try await withCheckedThrowingContinuation {
      (continuation: CheckedContinuation<Bool, Error>) in
      context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) {
        success, authenticationError in
        if let authenticationError {
          continuation.resume(throwing: authenticationError)
        } else {
          continuation.resume(returning: success)
        }
      }
    }
    guard accepted else { throw ApprovalAuthenticationError.failed }
    let verifiedAt = Date()
    return ApprovalUserPresenceProof(
      requestDigest: requestDigest,
      verifiedAt: verifiedAt,
      expiresAt: verifiedAt.addingTimeInterval(30)
    )
  }
}

public struct PreparedApprovalResolution: Equatable, Sendable {
  public let requestID: String
  public let rpcID: Int64
  public let threadID: String
  public let turnID: String
  public let response: JSONValue
  public let shouldInterruptTurn: Bool
}

struct PendingApprovalRegistry: Sendable {
  private struct Record: Sendable {
    let rpcID: Int64
    let method: String
    let params: JSONValue
    var summary: CompanionPendingApproval
  }

  private static let lifetime: TimeInterval = 120
  private var records: [String: Record] = [:]

  mutating func ingest(
    rpcID: Int64,
    method: String,
    params: JSONValue,
    now: Date
  ) throws -> CompanionPendingApproval {
    let kind: CompanionApprovalKind
    switch method {
    case "item/commandExecution/requestApproval":
      kind = params["networkApprovalContext"] == .null ? .command : .network
    case "item/fileChange/requestApproval":
      kind = .fileChange
    case "item/permissions/requestApproval":
      kind = .permissions
    default:
      throw PendingApprovalError.unsupportedRequest
    }

    guard let threadID = validID(params["threadId"].string),
      let turnID = validID(params["turnId"].string),
      let itemID = validID(params["itemId"].string),
      let startedAtMilliseconds = params["startedAtMs"].integer
    else {
      throw PendingApprovalError.invalidRequest
    }
    let createdAt = Date(timeIntervalSince1970: Double(startedAtMilliseconds) / 1_000)
    guard createdAt <= now.addingTimeInterval(30) else {
      throw PendingApprovalError.invalidTimestamp
    }
    let expiresAt = createdAt.addingTimeInterval(Self.lifetime)
    guard expiresAt > now else { throw PendingApprovalError.expired }

    let requestID = String(rpcID)
    let digest = try CanonicalJSON.digest(
      .object([
        "method": .string(method),
        "params": params,
        "rpcId": .integer(rpcID),
      ])
    )
    if let existing = records[requestID] {
      guard constantTimeEqual(existing.summary.requestDigest, digest) else {
        throw PendingApprovalError.requestIDCollision
      }
      return existing.summary
    }

    let summary = CompanionPendingApproval(
      requestID: requestID,
      threadID: threadID,
      turnID: turnID,
      itemID: itemID,
      kind: kind,
      availableDecisions: [.approveOnce, .decline, .cancel],
      requestDigest: digest,
      createdAt: createdAt,
      expiresAt: expiresAt,
      status: .pending
    )
    records[requestID] = Record(
      rpcID: rpcID,
      method: method,
      params: params,
      summary: summary
    )
    return summary
  }

  mutating func prepareResolution(
    requestID: String,
    requestDigest: String,
    decision: CompanionApprovalDecision,
    userPresence: ApprovalUserPresenceProof?,
    now: Date
  ) throws -> PreparedApprovalResolution {
    guard var record = records[requestID] else { throw PendingApprovalError.missingRequest }
    guard record.summary.status == .pending else { throw PendingApprovalError.notPending }
    guard record.summary.expiresAt > now else {
      records.removeValue(forKey: requestID)
      throw PendingApprovalError.expired
    }
    guard constantTimeEqual(record.summary.requestDigest, requestDigest) else {
      throw PendingApprovalError.digestMismatch
    }
    if decision == .approveOnce {
      guard let userPresence else { throw PendingApprovalError.userPresenceRequired }
      guard constantTimeEqual(userPresence.requestDigest, requestDigest),
        userPresence.verifiedAt <= now.addingTimeInterval(5),
        userPresence.expiresAt >= now
      else {
        throw PendingApprovalError.invalidUserPresence
      }
    }

    let response: JSONValue
    let shouldInterruptTurn: Bool
    switch record.summary.kind {
    case .command, .fileChange, .network:
      let codexDecision =
        switch decision {
        case .approveOnce: "accept"
        case .decline: "decline"
        case .cancel: "cancel"
        }
      response = .object(["decision": .string(codexDecision)])
      shouldInterruptTurn = false
    case .permissions:
      let grantedPermissions =
        decision == .approveOnce ? record.params["permissions"] : .object([:])
      response = .object([
        "permissions": grantedPermissions,
        "scope": .string("turn"),
        "strictAutoReview": .bool(true),
      ])
      shouldInterruptTurn = decision == .cancel
    }

    record.summary = record.summary.withStatus(.resolving)
    records[requestID] = record
    return PreparedApprovalResolution(
      requestID: requestID,
      rpcID: record.rpcID,
      threadID: record.summary.threadID,
      turnID: record.summary.turnID,
      response: response,
      shouldInterruptTurn: shouldInterruptTurn
    )
  }

  mutating func markResolved(requestID: String) {
    records.removeValue(forKey: requestID)
  }

  mutating func markOutcomeUnknown(requestID: String) throws {
    guard var record = records[requestID] else { throw PendingApprovalError.missingRequest }
    guard record.summary.status == .resolving else { throw PendingApprovalError.notPending }
    record.summary = record.summary.withStatus(.outcomeUnknown)
    records[requestID] = record
  }

  mutating func handleResolvedNotification(_ params: JSONValue) {
    if let requestID = params["requestId"].string {
      records.removeValue(forKey: requestID)
    } else if let requestID = params["requestId"].integer {
      records.removeValue(forKey: String(requestID))
    }
  }

  mutating func summaries(now: Date) -> [CompanionPendingApproval] {
    for requestID in Array(records.keys)
    where
      records[requestID]?.summary.status == .pending
      && records[requestID]?.summary.expiresAt ?? .distantPast <= now
    {
      records.removeValue(forKey: requestID)
    }
    return records.values.map(\.summary).sorted { $0.requestID < $1.requestID }
  }

  private func validID(_ value: String?) -> String? {
    guard let value, !value.isEmpty, value.utf8.count <= 256,
      value == value.trimmingCharacters(in: .whitespacesAndNewlines),
      !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    else { return nil }
    return value
  }

  private func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for index in left.indices {
      difference |= left[index] ^ right[index]
    }
    return difference == 0
  }
}
