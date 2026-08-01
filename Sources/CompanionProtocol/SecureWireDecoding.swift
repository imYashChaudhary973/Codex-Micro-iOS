import Foundation

/// Raised when a secure wire field violates its declared length, character, or
/// consistency bounds. The associated field name is a compile-time constant and
/// never contains wire content.
public enum SecureWireValidationError: Error, Equatable, Sendable {
  case invalidField(name: String)
}

struct WireDynamicCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init?(stringValue: String) {
    self.stringValue = stringValue
  }

  init?(intValue: Int) {
    return nil
  }
}

func rejectUnknownKeys(decoder: Decoder, allowed: Set<String>) throws {
  let container = try decoder.container(keyedBy: WireDynamicCodingKey.self)
  let received = Set(container.allKeys.map(\.stringValue))
  guard received.isSubset(of: allowed) else {
    throw DecodingError.dataCorrupted(
      .init(
        codingPath: decoder.codingPath,
        debugDescription: "Message contains unsupported fields."
      )
    )
  }
}

func strictContainer<Key: CodingKey & CaseIterable>(
  from decoder: Decoder,
  keyedBy type: Key.Type
) throws -> KeyedDecodingContainer<Key> {
  try rejectUnknownKeys(decoder: decoder, allowed: Set(type.allCases.map(\.stringValue)))
  return try decoder.container(keyedBy: type)
}

func requireExactByteCount(_ data: Data, _ count: Int, field: String) throws {
  guard data.count == count else {
    throw SecureWireValidationError.invalidField(name: field)
  }
}

func requireByteCount(_ data: Data, in range: ClosedRange<Int>, field: String) throws {
  guard range.contains(data.count) else {
    throw SecureWireValidationError.invalidField(name: field)
  }
}

func requireBoundedText(_ value: String, maxUTF8: Int, field: String) throws {
  guard !value.isEmpty, value.utf8.count <= maxUTF8,
    !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  else {
    throw SecureWireValidationError.invalidField(name: field)
  }
}
