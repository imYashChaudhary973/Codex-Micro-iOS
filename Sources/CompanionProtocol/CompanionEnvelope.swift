import Foundation

public struct CompanionEnvelope<Payload: Codable & Sendable>: Codable, Sendable {
  public let protocolVersion: ProtocolVersion
  public let messageID: UUID
  public let hostID: UUID
  public let sequence: UInt64?
  public let sentAt: Date
  public let payload: Payload

  public init(
    protocolVersion: ProtocolVersion = .current,
    messageID: UUID,
    hostID: UUID,
    sequence: UInt64?,
    sentAt: Date,
    payload: Payload
  ) {
    self.protocolVersion = protocolVersion
    self.messageID = messageID
    self.hostID = hostID
    self.sequence = sequence
    self.sentAt = sentAt
    self.payload = payload
  }
}

extension CompanionEnvelope: Equatable where Payload: Equatable {}
