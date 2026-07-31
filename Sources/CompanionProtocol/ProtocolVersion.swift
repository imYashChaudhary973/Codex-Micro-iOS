public struct ProtocolVersion: Codable, Equatable, Hashable, Sendable {
  public static let current = ProtocolVersion(major: 1, minor: 1)

  public let major: UInt16
  public let minor: UInt16

  public init(major: UInt16, minor: UInt16) {
    self.major = major
    self.minor = minor
  }

  public func isCompatible(with other: ProtocolVersion) -> Bool {
    major == other.major
  }
}
