/// Closed vocabulary of negotiable Phase 2 protocol features.
///
/// Unknown feature identifiers fail decoding closed. Phase 2 deliberately
/// defines **no approval feature**: `resolveApproval` is rejected by the
/// network gateway throughout Phase 2, so no case may represent it.
public enum SecureProtocolFeature: String, Codable, CaseIterable, Sendable {
  /// Filtered snapshot, event, and replay observation.
  case observeSync = "observe-sync-v1"
  /// The `interruptTurn` command path through the central gateway.
  case turnInterrupt = "turn-interrupt-v1"
  /// The `markThreadRead` device-own read-cursor mutation.
  case threadReadCursor = "thread-read-cursor-v1"
}

/// An exact `(major, minor, feature set)` tuple. The client proposes one; the
/// server accepts only exact supported values and echoes the same tuple back.
public struct SecureProtocolSelection: Codable, Equatable, Sendable {
  public let major: UInt16
  public let minor: UInt16
  public let features: Set<SecureProtocolFeature>

  public init(major: UInt16, minor: UInt16, features: Set<SecureProtocolFeature>) throws {
    guard (1...SecureTransportLimits.maxFeatureCount).contains(features.count) else {
      throw SecureWireValidationError.invalidField(name: "features")
    }
    self.major = major
    self.minor = minor
    self.features = features
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    let list = try container.decode([SecureProtocolFeature].self, forKey: .features)
    let set = Set(list)
    guard set.count == list.count else {
      throw SecureWireValidationError.invalidField(name: "features")
    }
    try self.init(
      major: container.decode(UInt16.self, forKey: .major),
      minor: container.decode(UInt16.self, forKey: .minor),
      features: set
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(major, forKey: .major)
    try container.encode(minor, forKey: .minor)
    try container.encode(features.sorted { $0.rawValue < $1.rawValue }, forKey: .features)
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case major
    case minor
    case features
  }
}

/// Closed negotiation failure vocabulary; carries no proposal content.
public enum SecureProtocolNegotiationError: Error, Equatable, Sendable {
  case unsupportedMajor
  case unsupportedMinor
  case unsupportedFeature
}

/// Exact minor/feature negotiation. There is no unconditional future-minor
/// acceptance: a minor or feature outside the exact supported sets fails
/// closed, and the accepted selection is always the client's exact proposal.
public enum SecureProtocolNegotiation {
  /// The only protocol major this build speaks.
  public static let supportedMajor: UInt16 = 1
  /// The exact set of supported minors. Future minors are not accepted.
  public static let supportedMinors: Set<UInt16> = [1]
  /// The exact set of supported features. No approval feature exists.
  public static let supportedFeatures = Set(SecureProtocolFeature.allCases)

  public static func accept(
    _ proposal: SecureProtocolSelection,
    supportedMajor: UInt16 = SecureProtocolNegotiation.supportedMajor,
    supportedMinors: Set<UInt16> = SecureProtocolNegotiation.supportedMinors,
    supportedFeatures: Set<SecureProtocolFeature> = SecureProtocolNegotiation.supportedFeatures
  ) throws -> SecureProtocolSelection {
    guard proposal.major == supportedMajor else {
      throw SecureProtocolNegotiationError.unsupportedMajor
    }
    guard supportedMinors.contains(proposal.minor) else {
      throw SecureProtocolNegotiationError.unsupportedMinor
    }
    guard proposal.features.isSubset(of: supportedFeatures) else {
      throw SecureProtocolNegotiationError.unsupportedFeature
    }
    return proposal
  }
}
