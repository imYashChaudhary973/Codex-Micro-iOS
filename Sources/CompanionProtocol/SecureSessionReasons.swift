import Foundation

/// Closed vocabulary for recoverable in-session problem reports. There is no
/// free-form string payload on any diagnostic path.
public enum SecureProblemReason: String, Codable, CaseIterable, Sendable {
  case malformedMessage
  case unsupportedMessage
  case boundsExceeded
  case invalidCursor
  case notAuthenticated
  case notAuthorized
  case subscriptionUnknown
  case rateLimited
  case temporarilyUnavailable
}

/// Closed vocabulary for terminal connection closes. Pre-authentication
/// closes are collapsed so they reveal no device, grant, or session state.
public enum SecureCloseReason: String, Codable, CaseIterable, Sendable {
  case protocolViolation
  case versionUnsupported
  case featureUnsupported
  case pairingFailed
  case authenticationFailed
  case sessionReplaced
  case deviceRevoked
  case grantExpired
  case authorizationChanged
  case counterViolation
  case frameViolation
  case messageBoundsExceeded
  case rateLimited
  case idleExpired
  case hostShuttingDown
}

/// A recoverable problem notice. Carries exactly one closed reason code.
public struct SecureProblemNotice: Codable, Equatable, Sendable {
  public let reason: SecureProblemReason

  public init(reason: SecureProblemReason) {
    self.reason = reason
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    self.init(reason: try container.decode(SecureProblemReason.self, forKey: .reason))
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case reason
  }
}

/// A terminal close notice. Carries exactly one closed reason code.
public struct SecureCloseNotice: Codable, Equatable, Sendable {
  public let reason: SecureCloseReason

  public init(reason: SecureCloseReason) {
    self.reason = reason
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    self.init(reason: try container.decode(SecureCloseReason.self, forKey: .reason))
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case reason
  }
}
