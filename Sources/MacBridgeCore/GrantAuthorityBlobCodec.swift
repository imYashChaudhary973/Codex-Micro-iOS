import Foundation

/// Versioned canonical blob codec for ``GrantAuthorityState`` (ADR §10/§11).
///
/// Follows the canonical contract: leading version byte, a length-prefixed
/// ASCII domain separator unique to this record type, fixed-width big-endian
/// integers, `UInt16` length prefixes on every variable field, explicit
/// presence bytes for optionals, and no trailing bytes. Device records and
/// set members are ordered strictly ascending by their encoded bytes, so the
/// encoding is deterministic and duplicates cannot decode. Any violation
/// decodes as ``DeviceGrantAuthorityError/corruptAuthority``; the 64 KiB
/// bound is enforced incrementally on encode and before decode.
enum GrantAuthorityBlobCodec {
  static let version: UInt8 = 1
  static let domain = "codex-micro/device-grant-authority/v1"

  static func encode(_ state: GrantAuthorityState) throws -> Data {
    guard state.hostGeneration >= 1, state.authoritySequence >= 1,
      state.grants.count <= Int(UInt16.max),
      state.grants.allSatisfy({ $0.key == $0.value.deviceID }),
      Set(state.grants.values.map(\.deviceID)).count == state.grants.count
    else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }

    var blob = Data()
    try appendByte(version, to: &blob)
    try appendVariableBytes(Data(domain.utf8), to: &blob)
    try appendUInt64(state.hostGeneration, to: &blob)
    try appendUInt64(state.authoritySequence, to: &blob)
    let orderedGrants = state.grants.values.sorted {
      encodedBytes($0.deviceID).lexicographicallyPrecedes(encodedBytes($1.deviceID))
    }
    try appendCount(orderedGrants.count, to: &blob)
    for grant in orderedGrants {
      try appendGrant(grant, to: &blob)
    }
    return blob
  }

  static func decode(_ blob: Data) throws -> GrantAuthorityState {
    guard blob.count <= GrantAuthorityLimits.maximumBlobByteCount else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    var reader = BlobReader(blob)
    guard try reader.readByte() == version,
      try reader.readVariableBytes() == Data(domain.utf8)
    else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    let hostGeneration = try reader.readUInt64()
    let authoritySequence = try reader.readUInt64()
    guard hostGeneration >= 1, authoritySequence >= 1 else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    let grantCount = Int(try reader.readUInt16())
    var grants: [UUID: AuthoritativeDeviceGrant] = [:]
    var previousDeviceIDBytes: Data?
    for _ in 0..<grantCount {
      let grant = try readGrant(from: &reader)
      let deviceIDBytes = encodedBytes(grant.deviceID)
      if let previousDeviceIDBytes {
        guard previousDeviceIDBytes.lexicographicallyPrecedes(deviceIDBytes) else {
          throw DeviceGrantAuthorityError.corruptAuthority
        }
      }
      previousDeviceIDBytes = deviceIDBytes
      grants[grant.deviceID] = grant
    }
    try reader.requireEnd()
    return GrantAuthorityState(
      hostGeneration: hostGeneration,
      authoritySequence: authoritySequence,
      grants: grants
    )
  }

  // MARK: - Grant record layout

  private static func appendGrant(
    _ grant: AuthoritativeDeviceGrant,
    to blob: inout Data
  ) throws {
    try appendBytes(encodedBytes(grant.deviceID), to: &blob)
    try appendVariableBytes(grant.devicePublicKey, to: &blob)
    try appendUInt64(grant.createdAtEpochSeconds, to: &blob)
    try appendUInt64(grant.lastSeenAtEpochSeconds, to: &blob)
    let capabilities = grant.capabilities.map { Data($0.rawValue.utf8) }.sorted {
      $0.lexicographicallyPrecedes($1)
    }
    try appendCount(capabilities.count, to: &blob)
    for capability in capabilities {
      try appendVariableBytes(capability, to: &blob)
    }
    let projectIDs = grant.permittedProjectIDs.map { Data($0.utf8) }.sorted {
      $0.lexicographicallyPrecedes($1)
    }
    try appendCount(projectIDs.count, to: &blob)
    for projectID in projectIDs {
      try appendVariableBytes(projectID, to: &blob)
    }
    try appendVariableBytes(Data(grant.actionProfileCeiling.rawValue.utf8), to: &blob)
    try appendUInt64(grant.grantRevision, to: &blob)
    try appendUInt64(grant.authorizedViewEpoch, to: &blob)
    if let expiresAt = grant.expiresAtEpochSeconds {
      try appendByte(1, to: &blob)
      try appendUInt64(expiresAt, to: &blob)
    } else {
      try appendByte(0, to: &blob)
    }
    if let tombstone = grant.tombstone {
      try appendByte(1, to: &blob)
      try appendByte(tombstone.kind == .revoked ? 0 : 1, to: &blob)
      try appendUInt64(tombstone.tombstonedAtEpochSeconds, to: &blob)
    } else {
      try appendByte(0, to: &blob)
    }
  }

  private static func readGrant(
    from reader: inout BlobReader
  ) throws -> AuthoritativeDeviceGrant {
    let deviceID = try reader.readUUID()
    let devicePublicKey = try reader.readVariableBytes()
    let createdAt = try reader.readUInt64()
    let lastSeen = try reader.readUInt64()
    let capabilityBytes = try readOrderedByteSet(
      from: &reader,
      maximumCount: DeviceCapability.allCases.count
    )
    let projectBytes = try readOrderedByteSet(
      from: &reader,
      maximumCount: GrantAuthorityLimits.maxProjectCount
    )
    guard
      let actionProfile = MobileActionProfile(
        rawValue: try readUTF8(from: &reader))
    else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    let grantRevision = try reader.readUInt64()
    let authorizedViewEpoch = try reader.readUInt64()
    let expiresAt: UInt64?
    switch try reader.readByte() {
    case 0:
      expiresAt = nil
    case 1:
      expiresAt = try reader.readUInt64()
    default:
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    let tombstone: DeviceGrantTombstone?
    switch try reader.readByte() {
    case 0:
      tombstone = nil
    case 1:
      let kind: DeviceGrantTombstone.Kind
      switch try reader.readByte() {
      case 0:
        kind = .revoked
      case 1:
        kind = .expired
      default:
        throw DeviceGrantAuthorityError.corruptAuthority
      }
      tombstone = DeviceGrantTombstone(
        kind: kind,
        tombstonedAtEpochSeconds: try reader.readUInt64()
      )
    default:
      throw DeviceGrantAuthorityError.corruptAuthority
    }

    var capabilities: Set<DeviceCapability> = []
    for bytes in capabilityBytes {
      guard let value = String(bytes: bytes, encoding: .utf8),
        let capability = DeviceCapability(rawValue: value)
      else {
        throw DeviceGrantAuthorityError.corruptAuthority
      }
      capabilities.insert(capability)
    }
    var projectIDs: Set<String> = []
    for bytes in projectBytes {
      guard let projectID = String(bytes: bytes, encoding: .utf8) else {
        throw DeviceGrantAuthorityError.corruptAuthority
      }
      projectIDs.insert(projectID)
    }
    guard projectIDs.count == projectBytes.count else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }

    do {
      return try AuthoritativeDeviceGrant(
        deviceID: deviceID,
        devicePublicKey: devicePublicKey,
        createdAtEpochSeconds: createdAt,
        lastSeenAtEpochSeconds: lastSeen,
        capabilities: capabilities,
        permittedProjectIDs: projectIDs,
        actionProfileCeiling: actionProfile,
        grantRevision: grantRevision,
        authorizedViewEpoch: authorizedViewEpoch,
        expiresAtEpochSeconds: expiresAt,
        tombstone: tombstone
      )
    } catch {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
  }

  /// Reads a strictly ascending, duplicate-free bounded byte-string list.
  private static func readOrderedByteSet(
    from reader: inout BlobReader,
    maximumCount: Int
  ) throws -> [Data] {
    let count = Int(try reader.readUInt16())
    guard count <= maximumCount else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    var values: [Data] = []
    values.reserveCapacity(count)
    for _ in 0..<count {
      let value = try reader.readVariableBytes()
      if let previous = values.last {
        guard previous.lexicographicallyPrecedes(value) else {
          throw DeviceGrantAuthorityError.corruptAuthority
        }
      }
      values.append(value)
    }
    return values
  }

  private static func readUTF8(from reader: inout BlobReader) throws -> String {
    let bytes = try reader.readVariableBytes()
    guard let value = String(bytes: bytes, encoding: .utf8) else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    return value
  }

  // MARK: - Primitive encoding

  private static func appendByte(_ value: UInt8, to blob: inout Data) throws {
    try appendBytes(Data([value]), to: &blob)
  }

  private static func appendCount(_ count: Int, to blob: inout Data) throws {
    guard count <= Int(UInt16.max) else {
      throw DeviceGrantAuthorityError.authorityOversized
    }
    try appendUInt16(UInt16(count), to: &blob)
  }

  private static func appendUInt16(_ value: UInt16, to blob: inout Data) throws {
    try appendBytes(Data(withUnsafeBytes(of: value.bigEndian) { Array($0) }), to: &blob)
  }

  private static func appendUInt64(_ value: UInt64, to blob: inout Data) throws {
    try appendBytes(Data(withUnsafeBytes(of: value.bigEndian) { Array($0) }), to: &blob)
  }

  private static func appendVariableBytes(_ data: Data, to blob: inout Data) throws {
    guard data.count <= Int(UInt16.max) else {
      throw DeviceGrantAuthorityError.authorityOversized
    }
    try appendUInt16(UInt16(data.count), to: &blob)
    try appendBytes(data, to: &blob)
  }

  private static func appendBytes(_ data: Data, to blob: inout Data) throws {
    guard data.count <= GrantAuthorityLimits.maximumBlobByteCount - blob.count else {
      throw DeviceGrantAuthorityError.authorityOversized
    }
    blob.append(data)
  }

  private static func encodedBytes(_ id: UUID) -> Data {
    withUnsafeBytes(of: id.uuid) { Data($0) }
  }

  private struct BlobReader {
    private let bytes: Data
    private var offset = 0

    init(_ blob: Data) {
      bytes = Data(blob)
    }

    mutating func readByte() throws -> UInt8 {
      try take(1)[0]
    }

    mutating func readUInt16() throws -> UInt16 {
      try take(2).reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
    }

    mutating func readUInt64() throws -> UInt64 {
      try take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    mutating func readUUID() throws -> UUID {
      let raw = Array(try take(16))
      return UUID(
        uuid: (
          raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
          raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
        ))
    }

    mutating func readVariableBytes() throws -> Data {
      let count = Int(try readUInt16())
      return try take(count)
    }

    func requireEnd() throws {
      guard offset == bytes.count else {
        throw DeviceGrantAuthorityError.corruptAuthority
      }
    }

    private mutating func take(_ count: Int) throws -> Data {
      guard bytes.count - offset >= count else {
        throw DeviceGrantAuthorityError.corruptAuthority
      }
      defer { offset += count }
      return bytes.subdata(in: offset..<(offset + count))
    }
  }
}
