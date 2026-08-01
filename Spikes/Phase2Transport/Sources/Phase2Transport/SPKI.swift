import CryptoKit
import Foundation
import Security

public enum SPKIError: Error, Equatable {
  case invalidP256PublicKey
}

public enum P256SPKI {
  private static let prefix = Data([
    0x30, 0x59,
    0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00,
  ])

  public static func der(uncompressedPoint: Data) throws -> Data {
    guard uncompressedPoint.count == 65, uncompressedPoint.first == 0x04 else {
      throw SPKIError.invalidP256PublicKey
    }
    return prefix + uncompressedPoint
  }

  public static func der(publicKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let representation = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      if let error {
        throw error.takeRetainedValue()
      }
      throw SPKIError.invalidP256PublicKey
    }
    return try der(uncompressedPoint: representation)
  }

  public static func sha256(_ der: Data) -> Data {
    Data(SHA256.hash(data: der))
  }

  public static func matches(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for (left, right) in zip(lhs, rhs) {
      difference |= left ^ right
    }
    return difference == 0
  }
}
