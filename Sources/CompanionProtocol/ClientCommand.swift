import Foundation

public enum CompanionCommandKind: String, Codable, CaseIterable, Sendable {
  case selectThread
  case startThread
  case sendPrompt
  case steerTurn
  case interruptTurn
  case resolveApproval
  case markThreadRead
}

public enum CompanionApprovalDecision: String, Codable, Sendable {
  case approveOnce
  case decline
  case cancel
}

public struct ClientCommand: Codable, Equatable, Sendable {
  public let commandID: UUID
  public let issuedAt: Date
  public let body: ClientCommandBody

  public init(commandID: UUID, issuedAt: Date, body: ClientCommandBody) throws {
    try body.validate()
    self.commandID = commandID
    self.issuedAt = issuedAt
    self.body = body
  }

  public init(from decoder: Decoder) throws {
    try rejectUnknownKeys(
      decoder: decoder,
      allowed: ["commandID", "issuedAt", "body"]
    )
    let container = try decoder.container(keyedBy: CodingKeys.self)
    commandID = try container.decode(UUID.self, forKey: .commandID)
    issuedAt = try container.decode(Date.self, forKey: .issuedAt)
    body = try container.decode(ClientCommandBody.self, forKey: .body)
    try body.validate()
  }

  private enum CodingKeys: String, CodingKey {
    case commandID
    case issuedAt
    case body
  }
}

public enum ClientCommandBody: Equatable, Sendable {
  case selectThread(threadID: String)
  case startThread(projectID: String, prompt: String, attachmentIDs: [String])
  case sendPrompt(threadID: String, prompt: String, attachmentIDs: [String])
  case steerTurn(threadID: String, turnID: String, prompt: String)
  case interruptTurn(threadID: String, turnID: String)
  case resolveApproval(
    requestID: String,
    decision: CompanionApprovalDecision,
    requestDigest: String
  )
  case markThreadRead(threadID: String, throughSequence: UInt64)

  public var kind: CompanionCommandKind {
    switch self {
    case .selectThread: .selectThread
    case .startThread: .startThread
    case .sendPrompt: .sendPrompt
    case .steerTurn: .steerTurn
    case .interruptTurn: .interruptTurn
    case .resolveApproval: .resolveApproval
    case .markThreadRead: .markThreadRead
    }
  }

  public func validate() throws {
    switch self {
    case .selectThread(let threadID):
      try validateOpaqueID(threadID, field: "threadId")
    case .startThread(let projectID, let prompt, let attachmentIDs):
      try validateOpaqueID(projectID, field: "projectId")
      try validatePrompt(prompt)
      try validateAttachments(attachmentIDs)
    case .sendPrompt(let threadID, let prompt, let attachmentIDs):
      try validateOpaqueID(threadID, field: "threadId")
      try validatePrompt(prompt)
      try validateAttachments(attachmentIDs)
    case .steerTurn(let threadID, let turnID, let prompt):
      try validateOpaqueID(threadID, field: "threadId")
      try validateOpaqueID(turnID, field: "turnId")
      try validatePrompt(prompt)
    case .interruptTurn(let threadID, let turnID):
      try validateOpaqueID(threadID, field: "threadId")
      try validateOpaqueID(turnID, field: "turnId")
    case .resolveApproval(let requestID, _, let requestDigest):
      try validateOpaqueID(requestID, field: "requestId")
      guard requestDigest.utf8.count == 64,
        requestDigest.utf8.allSatisfy({ byte in
          (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
            || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
        })
      else {
        throw CompanionCommandValidationError.invalidRequestDigest
      }
    case .markThreadRead(let threadID, _):
      try validateOpaqueID(threadID, field: "threadId")
    }
  }

  private func validateOpaqueID(_ value: String, field: String) throws {
    guard !value.isEmpty, value.utf8.count <= 256,
      value == value.trimmingCharacters(in: .whitespacesAndNewlines),
      !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
    else {
      throw CompanionCommandValidationError.invalidOpaqueID(field: field)
    }
  }

  private func validatePrompt(_ prompt: String) throws {
    guard !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      prompt.utf8.count <= 100_000
    else {
      throw CompanionCommandValidationError.invalidPrompt
    }
  }

  private func validateAttachments(_ attachmentIDs: [String]) throws {
    guard attachmentIDs.count <= 10 else {
      throw CompanionCommandValidationError.tooManyAttachments
    }
    for attachmentID in attachmentIDs {
      try validateOpaqueID(attachmentID, field: "attachmentId")
    }
  }
}

extension ClientCommandBody: Codable {
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let kind = try container.decode(CompanionCommandKind.self, forKey: .type)
    try rejectUnknownKeys(decoder: decoder, allowed: Self.allowedKeys(for: kind))

    switch kind {
    case .selectThread:
      self = .selectThread(threadID: try container.decode(String.self, forKey: .threadID))
    case .startThread:
      self = .startThread(
        projectID: try container.decode(String.self, forKey: .projectID),
        prompt: try container.decode(String.self, forKey: .prompt),
        attachmentIDs: try container.decodeIfPresent([String].self, forKey: .attachmentIDs) ?? []
      )
    case .sendPrompt:
      self = .sendPrompt(
        threadID: try container.decode(String.self, forKey: .threadID),
        prompt: try container.decode(String.self, forKey: .prompt),
        attachmentIDs: try container.decodeIfPresent([String].self, forKey: .attachmentIDs) ?? []
      )
    case .steerTurn:
      self = .steerTurn(
        threadID: try container.decode(String.self, forKey: .threadID),
        turnID: try container.decode(String.self, forKey: .turnID),
        prompt: try container.decode(String.self, forKey: .prompt)
      )
    case .interruptTurn:
      self = .interruptTurn(
        threadID: try container.decode(String.self, forKey: .threadID),
        turnID: try container.decode(String.self, forKey: .turnID)
      )
    case .resolveApproval:
      self = .resolveApproval(
        requestID: try container.decode(String.self, forKey: .requestID),
        decision: try container.decode(CompanionApprovalDecision.self, forKey: .decision),
        requestDigest: try container.decode(String.self, forKey: .requestDigest)
      )
    case .markThreadRead:
      self = .markThreadRead(
        threadID: try container.decode(String.self, forKey: .threadID),
        throughSequence: try container.decode(UInt64.self, forKey: .throughSequence)
      )
    }
    try validate()
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(kind, forKey: .type)

    switch self {
    case .selectThread(let threadID):
      try container.encode(threadID, forKey: .threadID)
    case .startThread(let projectID, let prompt, let attachmentIDs):
      try container.encode(projectID, forKey: .projectID)
      try container.encode(prompt, forKey: .prompt)
      try container.encode(attachmentIDs, forKey: .attachmentIDs)
    case .sendPrompt(let threadID, let prompt, let attachmentIDs):
      try container.encode(threadID, forKey: .threadID)
      try container.encode(prompt, forKey: .prompt)
      try container.encode(attachmentIDs, forKey: .attachmentIDs)
    case .steerTurn(let threadID, let turnID, let prompt):
      try container.encode(threadID, forKey: .threadID)
      try container.encode(turnID, forKey: .turnID)
      try container.encode(prompt, forKey: .prompt)
    case .interruptTurn(let threadID, let turnID):
      try container.encode(threadID, forKey: .threadID)
      try container.encode(turnID, forKey: .turnID)
    case .resolveApproval(let requestID, let decision, let requestDigest):
      try container.encode(requestID, forKey: .requestID)
      try container.encode(decision, forKey: .decision)
      try container.encode(requestDigest, forKey: .requestDigest)
    case .markThreadRead(let threadID, let throughSequence):
      try container.encode(threadID, forKey: .threadID)
      try container.encode(throughSequence, forKey: .throughSequence)
    }
  }

  private enum CodingKeys: String, CodingKey {
    case type
    case projectID
    case threadID
    case turnID
    case requestID
    case requestDigest
    case decision
    case prompt
    case attachmentIDs
    case throughSequence
  }

  private static func allowedKeys(for kind: CompanionCommandKind) -> Set<String> {
    switch kind {
    case .selectThread:
      ["type", "threadID"]
    case .startThread:
      ["type", "projectID", "prompt", "attachmentIDs"]
    case .sendPrompt:
      ["type", "threadID", "prompt", "attachmentIDs"]
    case .steerTurn:
      ["type", "threadID", "turnID", "prompt"]
    case .interruptTurn:
      ["type", "threadID", "turnID"]
    case .resolveApproval:
      ["type", "requestID", "decision", "requestDigest"]
    case .markThreadRead:
      ["type", "threadID", "throughSequence"]
    }
  }
}

public enum CompanionCommandValidationError: Error, Equatable, Sendable {
  case invalidOpaqueID(field: String)
  case invalidPrompt
  case invalidRequestDigest
  case tooManyAttachments
}

private struct DynamicCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init?(stringValue: String) {
    self.stringValue = stringValue
  }

  init?(intValue: Int) {
    return nil
  }
}

private func rejectUnknownKeys(decoder: Decoder, allowed: Set<String>) throws {
  let container = try decoder.container(keyedBy: DynamicCodingKey.self)
  let received = Set(container.allKeys.map(\.stringValue))
  guard received.isSubset(of: allowed) else {
    throw DecodingError.dataCorrupted(
      .init(
        codingPath: decoder.codingPath,
        debugDescription: "Command contains unsupported fields."
      )
    )
  }
}
