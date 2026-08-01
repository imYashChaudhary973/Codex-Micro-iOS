import Foundation
import Security

public enum TestOnlyEphemeralIdentityFactory {
  public static func make(role: SpikeIdentityRole = .tls) throws -> KeychainIdentity {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
      kSecAttrIsPermanent: false,
      kSecAttrIsSensitive: true,
      kSecAttrIsExtractable: false,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      let status =
        error.map { Int32(CFErrorGetCode($0.takeRetainedValue())) } ?? errSecInternalError
      throw KeychainIdentityError.keyCreation(status)
    }
    let identity = try KeychainIdentity(role: role, privateKey: key)
    try identity.assertPrivateKeyIsNonExportable()
    return identity
  }
}
