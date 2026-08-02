import CompanionProtocol
import Foundation

/// Version byte that leads every canonical security statement (ADR §11).
public enum CanonicalStatementVersion {
  /// The only canonical statement version this build produces or accepts.
  public static let current: UInt8 = 1
}

/// Closed set of ASCII domain-separator context strings (ADR §11).
///
/// No two statement or derivation contexts share a string, so a signature,
/// derived key, or short authentication string produced under one context can
/// never verify or reproduce under another. Every context string carries its
/// own version suffix; a future layout change mints a new context.
public enum CanonicalStatementDomain: String, CaseIterable, Sendable {
  case pairingQRPayload = "codex-micro/pairing-qr/v1"
  case pairingTranscript = "codex-micro/pairing-transcript/v1"
  case sessionTranscript = "codex-micro/session-transcript/v1"
  case rotationStatement = "codex-micro/rotation-statement/v1"
  case frameKeyClientToServer = "codex-micro/frame-key/client-to-server/v1"
  case frameKeyServerToClient = "codex-micro/frame-key/server-to-client/v1"
  case shortAuthenticationString = "codex-micro/sas/v1"
}

/// Injective canonical byte builder for security statements (ADR §11).
///
/// Layout rules, fixed for every statement type:
/// - The version byte leads, followed by the length-prefixed domain separator.
/// - Fields appear in one fixed declaration order per statement type.
/// - Integers are fixed-width big-endian.
/// - Every byte or UTF-8 text field is prefixed with a big-endian `UInt16`
///   byte length; there is no delimiter- or concatenation-ambiguous form.
/// - Optionals encode an explicit presence byte (`0x00` absent, `0x01`
///   present) before the encoded field.
struct CanonicalStatementEncoder {
  private(set) var encodedBytes = Data()

  init(domain: CanonicalStatementDomain) {
    encodedBytes.append(CanonicalStatementVersion.current)
    appendVariableBytes(Data(domain.rawValue.utf8))
  }

  mutating func appendUInt8(_ value: UInt8) {
    encodedBytes.append(value)
  }

  mutating func appendUInt16(_ value: UInt16) {
    withUnsafeBytes(of: value.bigEndian) { encodedBytes.append(contentsOf: $0) }
  }

  mutating func appendUInt32(_ value: UInt32) {
    withUnsafeBytes(of: value.bigEndian) { encodedBytes.append(contentsOf: $0) }
  }

  mutating func appendUInt64(_ value: UInt64) {
    withUnsafeBytes(of: value.bigEndian) { encodedBytes.append(contentsOf: $0) }
  }

  mutating func appendVariableBytes(_ data: Data) {
    precondition(data.count <= Int(UInt16.max), "canonical field exceeds UInt16 length prefix")
    appendUInt16(UInt16(data.count))
    encodedBytes.append(data)
  }

  mutating func appendText(_ value: String) {
    appendVariableBytes(Data(value.utf8))
  }

  mutating func appendUUID(_ value: UUID) {
    appendVariableBytes(Data(uuid: value))
  }

  mutating func appendOptionalVariableBytes(_ data: Data?) {
    guard let data else {
      appendUInt8(0)
      return
    }
    appendUInt8(1)
    appendVariableBytes(data)
  }

  mutating func appendSelection(_ selection: SecureProtocolSelection) {
    appendUInt16(selection.major)
    appendUInt16(selection.minor)
    let features = selection.features.sorted { $0.rawValue < $1.rawValue }
    appendUInt16(UInt16(features.count))
    for feature in features {
      appendText(feature.rawValue)
    }
  }
}

/// Strict reader for canonical statement bytes. Every violation — wrong
/// version, wrong domain, short data, wrong field length, or trailing bytes —
/// fails closed with a content-free field name.
struct CanonicalStatementReader {
  private let bytes: Data
  private var offset = 0

  init(_ encoded: Data, domain: CanonicalStatementDomain) throws {
    bytes = Data(encoded)
    guard try readUInt8() == CanonicalStatementVersion.current else {
      throw SecureWireValidationError.invalidField(name: "canonicalVersion")
    }
    guard try readVariableBytes() == Data(domain.rawValue.utf8) else {
      throw SecureWireValidationError.invalidField(name: "canonicalDomain")
    }
  }

  mutating func readUInt8() throws -> UInt8 {
    try take(1)[0]
  }

  mutating func readUInt16() throws -> UInt16 {
    try take(2).reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
  }

  mutating func readUInt64() throws -> UInt64 {
    try take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
  }

  mutating func readVariableBytes() throws -> Data {
    let count = Int(try readUInt16())
    return try take(count)
  }

  mutating func readVariableBytes(exactCount: Int) throws -> Data {
    let data = try readVariableBytes()
    guard data.count == exactCount else {
      throw SecureWireValidationError.invalidField(name: "canonicalFieldLength")
    }
    return data
  }

  mutating func readText() throws -> String {
    guard let text = String(data: try readVariableBytes(), encoding: .utf8) else {
      throw SecureWireValidationError.invalidField(name: "canonicalText")
    }
    return text
  }

  mutating func readUUID() throws -> UUID {
    UUID(canonicalBytes: try readVariableBytes(exactCount: 16))
  }

  /// Reads an exact protocol selection. Unknown, duplicate, or non-ascending
  /// feature identifiers fail closed, so one selection has one encoding.
  mutating func readSelection() throws -> SecureProtocolSelection {
    let major = try readUInt16()
    let minor = try readUInt16()
    let count = Int(try readUInt16())
    guard (1...SecureTransportLimits.maxFeatureCount).contains(count) else {
      throw SecureWireValidationError.invalidField(name: "features")
    }
    var features: [SecureProtocolFeature] = []
    features.reserveCapacity(count)
    for _ in 0..<count {
      guard let feature = SecureProtocolFeature(rawValue: try readText()) else {
        throw SecureWireValidationError.invalidField(name: "features")
      }
      if let previous = features.last, previous.rawValue >= feature.rawValue {
        throw SecureWireValidationError.invalidField(name: "features")
      }
      features.append(feature)
    }
    return try SecureProtocolSelection(major: major, minor: minor, features: Set(features))
  }

  func requireEnd() throws {
    guard offset == bytes.count else {
      throw SecureWireValidationError.invalidField(name: "canonicalTrailingBytes")
    }
  }

  private mutating func take(_ count: Int) throws -> Data {
    guard bytes.count - offset >= count else {
      throw SecureWireValidationError.invalidField(name: "canonicalLength")
    }
    defer { offset += count }
    return bytes.subdata(in: offset..<(offset + count))
  }
}

func requireExactCryptoByteCount(_ data: Data, _ count: Int, field: String) throws {
  guard data.count == count else {
    throw SecureWireValidationError.invalidField(name: field)
  }
}

func requireBoundedCryptoText(_ value: String, maxUTF8: Int, field: String) throws {
  guard !value.isEmpty, value.utf8.count <= maxUTF8,
    !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  else {
    throw SecureWireValidationError.invalidField(name: field)
  }
}

extension Data {
  init(uuid: UUID) {
    let raw = uuid.uuid
    self.init([
      raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6, raw.7,
      raw.8, raw.9, raw.10, raw.11, raw.12, raw.13, raw.14, raw.15,
    ])
  }
}

extension UUID {
  init(canonicalBytes: Data) {
    precondition(canonicalBytes.count == 16, "UUID requires exactly 16 bytes")
    let raw = [UInt8](canonicalBytes)
    self.init(
      uuid: (
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
      ))
  }
}
