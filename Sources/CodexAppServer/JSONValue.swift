import Foundation

public enum JSONValue: Codable, Equatable, Sendable {
  case object([String: JSONValue])
  case array([JSONValue])
  case string(String)
  case integer(Int64)
  case number(Double)
  case bool(Bool)
  case null

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()

    if container.decodeNil() {
      self = .null
    } else if let value = try? container.decode(Bool.self) {
      self = .bool(value)
    } else if let value = try? container.decode(Int64.self) {
      self = .integer(value)
    } else if let value = try? container.decode(Double.self) {
      self = .number(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode([JSONValue].self) {
      self = .array(value)
    } else {
      self = .object(try container.decode([String: JSONValue].self))
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()

    switch self {
    case .object(let value):
      try container.encode(value)
    case .array(let value):
      try container.encode(value)
    case .string(let value):
      try container.encode(value)
    case .integer(let value):
      try container.encode(value)
    case .number(let value):
      try container.encode(value)
    case .bool(let value):
      try container.encode(value)
    case .null:
      try container.encodeNil()
    }
  }

  public var object: [String: JSONValue]? {
    guard case .object(let value) = self else { return nil }
    return value
  }

  public var array: [JSONValue]? {
    guard case .array(let value) = self else { return nil }
    return value
  }

  public var string: String? {
    guard case .string(let value) = self else { return nil }
    return value
  }

  public var integer: Int64? {
    switch self {
    case .integer(let value):
      return value
    case .number(let value) where value.rounded() == value:
      return Int64(value)
    default:
      return nil
    }
  }

  public var bool: Bool? {
    guard case .bool(let value) = self else { return nil }
    return value
  }

  public subscript(key: String) -> JSONValue {
    object?[key] ?? .null
  }

  public func prettyPrinted() throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(self)
    return String(decoding: data, as: UTF8.self)
  }
}
