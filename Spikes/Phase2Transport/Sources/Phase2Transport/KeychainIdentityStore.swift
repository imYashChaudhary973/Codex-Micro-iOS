import Foundation
import Security

public enum SpikeIdentityRole: String, CaseIterable, Sendable {
  case host
  case tls
}

public enum KeychainIdentityError: Error, Equatable {
  case claimCreation(Int32)
  case cleanupFailures([Int32])
  case duplicate
  case incompleteCreation
  case invalidNamespace
  case keyCreation(Int32)
  case keyLookup(Int32)
  case keyMissing
  case keyMismatch
  case keyMultiplicity(Int)
  case privateKeyExported
  case publicKeyUnavailable
  case rollbackFailures([Int32])
  case signatureFailed
}

public struct SpikeKeychainNamespace: Equatable, Sendable {
  public static let prefix = "com.codexmicro.phase2transport.spike"
  public let runID: String

  public init(runID: String) throws {
    let isExplicitASCII = runID.utf8.allSatisfy { byte in
      (0x61...0x7A).contains(byte) || (0x30...0x39).contains(byte) || byte == 0x2D
    }
    guard (1...32).contains(runID.utf8.count), isExplicitASCII else {
      throw KeychainIdentityError.invalidNamespace
    }
    self.runID = runID
  }

  fileprivate func tag(for role: SpikeIdentityRole) -> Data {
    Data("\(Self.prefix).\(runID).\(role.rawValue).p256.v1".utf8)
  }

  fileprivate func claimAccount(for role: SpikeIdentityRole) -> String {
    "\(runID).\(role.rawValue).p256.v1"
  }
}

public enum ProbeKeychainNamespaceInventory {
  public static let certificateRunIDs = [
    "cert-host-probe",
    "cert-tls-probe",
    "cert-next-probe",
  ]

  public static func all(primaryRunID: String) throws -> [SpikeKeychainNamespace] {
    var runIDs = [primaryRunID]
    runIDs.append(contentsOf: certificateRunIDs)
    return try Array(Set(runIDs)).sorted().map(SpikeKeychainNamespace.init(runID:))
  }

  public static func cleanupAll(primaryRunID: String) throws {
    var failures: [Int32] = []
    for namespace in try all(primaryRunID: primaryRunID) {
      do {
        try KeychainIdentityStore(namespace: namespace).cleanup()
      } catch KeychainIdentityError.cleanupFailures(let statuses) {
        failures.append(contentsOf: statuses)
      }
    }
    guard failures.isEmpty else {
      throw KeychainIdentityError.cleanupFailures(failures)
    }
  }
}

public struct KeychainIdentity: @unchecked Sendable {
  public let role: SpikeIdentityRole
  public let privateKey: SecKey
  public let publicKey: SecKey
  public let spkiDER: Data
  public let spkiSHA256: Data

  init(role: SpikeIdentityRole, privateKey: SecKey) throws {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw KeychainIdentityError.publicKeyUnavailable
    }
    let spkiDER = try P256SPKI.der(publicKey: publicKey)
    self.role = role
    self.privateKey = privateKey
    self.publicKey = publicKey
    self.spkiDER = spkiDER
    self.spkiSHA256 = P256SPKI.sha256(spkiDER)
  }

  public func sign(_ message: Data) throws -> Data {
    let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
      throw KeychainIdentityError.signatureFailed
    }
    var error: Unmanaged<CFError>?
    guard
      let signature = SecKeyCreateSignature(privateKey, algorithm, message as CFData, &error)
        as Data?
    else {
      _ = error?.takeRetainedValue()
      throw KeychainIdentityError.signatureFailed
    }
    return signature
  }

  public func verify(signature: Data, message: Data) -> Bool {
    let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
    guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else { return false }
    var error: Unmanaged<CFError>?
    return SecKeyVerifySignature(
      publicKey,
      algorithm,
      message as CFData,
      signature as CFData,
      &error
    )
  }

  public func assertPrivateKeyIsNonExportable() throws {
    var error: Unmanaged<CFError>?
    if SecKeyCopyExternalRepresentation(privateKey, &error) != nil {
      throw KeychainIdentityError.privateKeyExported
    }
    _ = error?.takeRetainedValue()
  }
}

private final class KeychainCreateSerializer: @unchecked Sendable {
  static let shared = KeychainCreateSerializer()
  let lock = NSLock()
}

public struct KeychainIdentityStore: Sendable {
  private static let claimService = "\(SpikeKeychainNamespace.prefix).creation-claim"

  public let namespace: SpikeKeychainNamespace

  public init(namespace: SpikeKeychainNamespace) {
    self.namespace = namespace
  }

  public func create(role: SpikeIdentityRole) throws -> KeychainIdentity {
    try KeychainCreateSerializer.shared.lock.withLock {
      let claimStatus = SecItemAdd(claimAddQuery(role: role) as CFDictionary, nil)
      if claimStatus == errSecDuplicateItem {
        let keys = try matchingKeys(role: role)
        if keys.count == 1 {
          throw KeychainIdentityError.duplicate
        }
        if keys.isEmpty {
          throw KeychainIdentityError.incompleteCreation
        }
        throw KeychainIdentityError.keyMultiplicity(keys.count)
      }
      guard claimStatus == errSecSuccess else {
        throw KeychainIdentityError.claimCreation(claimStatus)
      }

      do {
        let existingKeys = try matchingKeys(role: role)
        guard existingKeys.isEmpty else {
          throw existingKeys.count == 1
            ? KeychainIdentityError.duplicate
            : KeychainIdentityError.keyMultiplicity(existingKeys.count)
        }

        let key = try createPermanentKey(role: role)
        do {
          let identity = try KeychainIdentity(role: role, privateKey: key)
          try identity.assertPrivateKeyIsNonExportable()
          let keys = try matchingKeys(role: role)
          guard keys.count == 1 else {
            throw KeychainIdentityError.keyMultiplicity(keys.count)
          }
          guard CFEqual(keys[0], key), try matchingClaimCount(role: role) == 1 else {
            throw KeychainIdentityError.keyMismatch
          }
          return identity
        } catch {
          try rollback(role: role, key: key)
          throw error
        }
      } catch {
        try rollback(role: role, key: nil)
        throw error
      }
    }
  }

  public func load(role: SpikeIdentityRole, expectedSPKISHA256: Data? = nil) throws
    -> KeychainIdentity
  {
    let claimCount = try matchingClaimCount(role: role)
    let keys = try matchingKeys(role: role)
    guard claimCount > 0 || !keys.isEmpty else { throw KeychainIdentityError.keyMissing }
    guard claimCount == 1, keys.count == 1 else {
      if claimCount == 1, keys.isEmpty {
        throw KeychainIdentityError.incompleteCreation
      }
      throw KeychainIdentityError.keyMultiplicity(keys.count)
    }
    let key = keys[0]
    try validateAttributes(key)
    let identity = try KeychainIdentity(role: role, privateKey: key)
    if let expectedSPKISHA256, !P256SPKI.matches(identity.spkiSHA256, expectedSPKISHA256) {
      throw KeychainIdentityError.keyMismatch
    }
    try identity.assertPrivateKeyIsNonExportable()
    return identity
  }

  public func cleanup(role: SpikeIdentityRole) throws {
    var failures: [Int32] = []
    let keyStatus = SecItemDelete(keyDeleteQuery(role: role) as CFDictionary)
    if keyStatus != errSecSuccess, keyStatus != errSecItemNotFound {
      failures.append(keyStatus)
    }
    let claimStatus = SecItemDelete(claimDeleteQuery(role: role) as CFDictionary)
    if claimStatus != errSecSuccess, claimStatus != errSecItemNotFound {
      failures.append(claimStatus)
    }
    do {
      if try !matchingKeys(role: role).isEmpty || matchingClaimCount(role: role) != 0 {
        failures.append(errSecDuplicateItem)
      }
    } catch KeychainIdentityError.keyLookup(let status) {
      failures.append(status)
    }
    guard failures.isEmpty else {
      throw KeychainIdentityError.cleanupFailures(failures)
    }
  }

  public func cleanup() throws {
    var failures: [Int32] = []
    for role in SpikeIdentityRole.allCases {
      do {
        try cleanup(role: role)
      } catch KeychainIdentityError.cleanupFailures(let statuses) {
        failures.append(contentsOf: statuses)
      }
    }
    guard failures.isEmpty else {
      throw KeychainIdentityError.cleanupFailures(failures)
    }
  }

  private func createPermanentKey(role: SpikeIdentityRole) throws -> SecKey {
    // A software key's scalar is always recoverable by the process that holds
    // its SecKey, regardless of Keychain attributes, so non-exportability must
    // come from the Secure Enclave token.
    var accessError: Unmanaged<CFError>?
    guard
      let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage],
        &accessError
      )
    else {
      let status =
        accessError.map { Int32(CFErrorGetCode($0.takeRetainedValue())) } ?? errSecInternalError
      throw KeychainIdentityError.keyCreation(status)
    }
    let privateAttributes: [CFString: Any] = [
      kSecAttrIsPermanent: true,
      kSecAttrApplicationTag: namespace.tag(for: role),
      kSecAttrLabel: "Phase2TransportSpike",
      kSecAttrAccessControl: accessControl,
    ]
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
      kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs: privateAttributes,
      kSecUseDataProtectionKeychain: true,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      let status =
        error.map { Int32(CFErrorGetCode($0.takeRetainedValue())) } ?? errSecInternalError
      throw KeychainIdentityError.keyCreation(status)
    }
    return key
  }

  private func rollback(role: SpikeIdentityRole, key: SecKey?) throws {
    var failures: [Int32] = []
    if let key {
      let keyStatus = deleteExact(key)
      if keyStatus != errSecSuccess, keyStatus != errSecItemNotFound {
        failures.append(keyStatus)
      }
    }
    let claimStatus = SecItemDelete(claimDeleteQuery(role: role) as CFDictionary)
    if claimStatus != errSecSuccess, claimStatus != errSecItemNotFound {
      failures.append(claimStatus)
    }
    guard failures.isEmpty else {
      throw KeychainIdentityError.rollbackFailures(failures)
    }
  }

  private func matchingKeys(role: SpikeIdentityRole) throws -> [SecKey] {
    let query: [CFString: Any] = [
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrApplicationTag: namespace.tag(for: role),
      kSecMatchLimit: kSecMatchLimitAll,
      kSecReturnRef: true,
      kSecUseDataProtectionKeychain: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else { return [] }
    guard status == errSecSuccess else { throw KeychainIdentityError.keyLookup(status) }
    guard let items = item as? [SecKey] else {
      throw KeychainIdentityError.keyMismatch
    }
    return items
  }

  private func matchingClaimCount(role: SpikeIdentityRole) throws -> Int {
    var query = claimDeleteQuery(role: role)
    query[kSecMatchLimit] = kSecMatchLimitAll
    query[kSecReturnAttributes] = true
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else { return 0 }
    guard status == errSecSuccess else { throw KeychainIdentityError.keyLookup(status) }
    guard let items = item as? [Any] else { throw KeychainIdentityError.keyMismatch }
    return items.count
  }

  private func claimAddQuery(role: SpikeIdentityRole) -> [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.claimService,
      kSecAttrAccount: namespace.claimAccount(for: role),
      kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData: Data([1]),
      kSecUseDataProtectionKeychain: true,
    ]
  }

  private func claimDeleteQuery(role: SpikeIdentityRole) -> [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: Self.claimService,
      kSecAttrAccount: namespace.claimAccount(for: role),
      kSecUseDataProtectionKeychain: true,
    ]
  }

  private func keyDeleteQuery(role: SpikeIdentityRole) -> [CFString: Any] {
    [
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecAttrApplicationTag: namespace.tag(for: role),
      kSecUseDataProtectionKeychain: true,
    ]
  }

  private func deleteExact(_ key: SecKey) -> OSStatus {
    let query: [CFString: Any] = [
      kSecClass: kSecClassKey,
      kSecValueRef: key,
      kSecUseDataProtectionKeychain: true,
    ]
    return SecItemDelete(query as CFDictionary)
  }

  private func validateAttributes(_ key: SecKey) throws {
    guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
      attributes[kSecAttrKeyClass] as? String == kSecAttrKeyClassPrivate as String,
      attributes[kSecAttrKeySizeInBits] as? Int == 256,
      attributes[kSecAttrTokenID] as? String == kSecAttrTokenIDSecureEnclave as String,
      (attributes[kSecAttrIsExtractable] as? Bool) != true
    else {
      throw KeychainIdentityError.keyMismatch
    }
  }
}
