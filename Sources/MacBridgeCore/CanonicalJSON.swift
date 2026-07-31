import CodexAppServer
import CryptoKit
import Foundation

enum CanonicalJSON {
  static func data(for value: JSONValue) throws -> Data {
    switch value {
    case .object(let object):
      var data = Data("{".utf8)
      for (index, key) in object.keys.sorted().enumerated() {
        if index > 0 { data.append(Data(",".utf8)) }
        data.append(try encodedScalar(key))
        data.append(Data(":".utf8))
        guard let child = object[key] else {
          throw CodexCompatibilityProbeError.invalidSchemaBundle
        }
        data.append(try self.data(for: child))
      }
      data.append(Data("}".utf8))
      return data
    case .array(let array):
      var data = Data("[".utf8)
      for (index, child) in array.enumerated() {
        if index > 0 { data.append(Data(",".utf8)) }
        data.append(try self.data(for: child))
      }
      data.append(Data("]".utf8))
      return data
    case .string(let string):
      return try encodedScalar(string)
    case .integer(let integer):
      return Data(String(integer).utf8)
    case .number(let number):
      return try encodedScalar(number)
    case .bool(let bool):
      return Data((bool ? "true" : "false").utf8)
    case .null:
      return Data("null".utf8)
    }
  }

  static func digest(_ value: JSONValue) throws -> String {
    SHA256.hash(data: try data(for: value))
      .map { String(format: "%02x", $0) }
      .joined()
  }

  private static func encodedScalar<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    return try encoder.encode(value)
  }
}
