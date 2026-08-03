import CryptoKit
import Foundation
import Security
import X509

/// Validated Keychain namespace for bridge identity items.
///
/// The label appears only inside Keychain application tags and claim
/// accounts; it is never logged or transmitted. Non-production namespaces
/// exist solely for entitled test isolation (Step 2.14).
public struct BridgeKeychainNamespace: Equatable, Sendable {
  /// The production namespace used by the running bridge.
  public static let production = BridgeKeychainNamespace(validatedLabel: "bridge")

  private static let tagPrefix = "com.codexmicro.identity"
  private static let claimService = "com.codexmicro.identity-claim"

  /// The validated namespace label (lowercase ASCII, digits, hyphen).
  public let label: String

  /// Creates a namespace with a validated label of 1–32 characters drawn
  /// from lowercase ASCII letters, digits, and hyphen.
  public init(label: String) throws {
    let isAllowedASCII = label.utf8.allSatisfy { byte in
      (0x61...0x7A).contains(byte) || (0x30...0x39).contains(byte) || byte == 0x2D
    }
    guard (1...32).contains(label.utf8.count), isAllowedASCII else {
      throw BridgeIdentityError.keyStoreFailure
    }
    self.label = label
  }

  private init(validatedLabel: String) {
    self.label = validatedLabel
  }

  func keyTag(for role: BridgeIdentityRole) -> Data {
    Data("\(Self.tagPrefix).\(label).\(role.rawValue).p256.v1".utf8)
  }

  var claimServiceName: String {
    Self.claimService
  }

  func claimAccount(for role: BridgeIdentityRole) -> String {
    "\(label).\(role.rawValue).p256.v1"
  }
}

/// A Secure Enclave private key held in the Data Protection Keychain.
///
/// The key was created with `kSecAttrTokenIDSecureEnclave`, a
/// `privateKeyUsage`-only access control, and
/// `AfterFirstUnlockThisDeviceOnly` accessibility, so the private scalar
/// physically cannot leave the Secure Enclave, no biometric prompt occurs
/// on normal use, and the item is never synced or backed up (ADR §6).
public final class SecureEnclaveIdentityKey: SecureIdentityKey {
  let secKey: SecKey

  init(secKey: SecKey) {
    self.secKey = secKey
  }

  public func publicKeyX963() throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(secKey) else {
      throw BridgeIdentityError.publicKeyUnavailable
    }
    var error: Unmanaged<CFError>?
    guard let representation = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      _ = error?.takeRetainedValue()
      throw BridgeIdentityError.publicKeyUnavailable
    }
    return representation
  }

  public func signRaw(_ message: Data) throws -> Data {
    let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
    guard SecKeyIsAlgorithmSupported(secKey, .sign, algorithm) else {
      throw BridgeIdentityError.signatureFailure
    }
    var error: Unmanaged<CFError>?
    guard
      let derSignature = SecKeyCreateSignature(secKey, algorithm, message as CFData, &error)
        as Data?
    else {
      _ = error?.takeRetainedValue()
      throw BridgeIdentityError.signatureFailure
    }
    guard let parsed = try? P256.Signing.ECDSASignature(derRepresentation: derSignature) else {
      throw BridgeIdentityError.signatureFailure
    }
    return parsed.rawRepresentation
  }

  public func validateRequiredAttributes() throws {
    guard let attributes = SecKeyCopyAttributes(secKey) as? [CFString: Any],
      attributes[kSecAttrKeyClass] as? String == kSecAttrKeyClassPrivate as String,
      attributes[kSecAttrKeySizeInBits] as? Int == 256,
      attributes[kSecAttrTokenID] as? String == kSecAttrTokenIDSecureEnclave as String,
      (attributes[kSecAttrIsExtractable] as? Bool) != true
    else {
      throw BridgeIdentityError.attributeMismatch
    }
  }

  public func assertNonExportable() throws {
    var error: Unmanaged<CFError>?
    if SecKeyCopyExternalRepresentation(secKey, &error) != nil {
      throw BridgeIdentityError.privateKeyExportable
    }
    _ = error?.takeRetainedValue()
  }

  public func certificateSigner() throws -> Certificate.PrivateKey {
    guard let signer = try? Certificate.PrivateKey(secKey) else {
      throw BridgeIdentityError.signatureFailure
    }
    return signer
  }
}

/// Production ``SecureIdentityBackend`` over the Secure Enclave and the
/// device-only Data Protection Keychain (ADR §6).
///
/// This backend only moves items; every lifecycle decision (claims,
/// rollback, validation ordering, fail-closed behavior) belongs to
/// ``BridgeIdentityStore``. Positive-path behavior requires an entitled,
/// signed process with Secure Enclave access; the merged spike evidence
/// proves that path and Step 2.14 re-proves it on-device. OSStatus values
/// are never propagated — failures map onto the closed
/// ``BridgeIdentityError`` vocabulary.
public final class SecureEnclaveIdentityBackend: SecureIdentityBackend {
  private static let creationLock = NSLock()

  private let namespace: BridgeKeychainNamespace

  /// Creates a backend over `namespace` (production by default).
  public init(namespace: BridgeKeychainNamespace = .production) {
    self.namespace = namespace
  }

  public func insertClaim(for role: BridgeIdentityRole) throws -> BridgeClaimInsertion {
    let attributes: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: namespace.claimServiceName,
      kSecAttrAccount: namespace.claimAccount(for: role),
      kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData: Data([1]),
      kSecUseDataProtectionKeychain: true,
    ]
    let status = SecItemAdd(attributes as CFDictionary, nil)
    switch status {
    case errSecSuccess:
      return .inserted
    case errSecDuplicateItem:
      return .alreadyPresent
    case errSecMissingEntitlement:
      throw BridgeIdentityError.entitlementMissing
    default:
      throw BridgeIdentityError.claimStoreFailure
    }
  }

  public func claimCount(for role: BridgeIdentityRole) throws -> Int {
    var query = claimQuery(for: role)
    query[kSecMatchLimit] = kSecMatchLimitAll
    query[kSecReturnAttributes] = true
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else { return 0 }
    guard status == errSecSuccess, let items = item as? [Any] else {
      throw BridgeIdentityError.claimStoreFailure
    }
    return items.count
  }

  public func removeClaim(for role: BridgeIdentityRole) throws {
    let status = SecItemDelete(claimQuery(for: role) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw BridgeIdentityError.claimStoreFailure
    }
  }

  public func createKey(for role: BridgeIdentityRole) throws -> any SecureIdentityKey {
    // A software key's scalar is always recoverable by the process holding
    // its SecKey regardless of Keychain attributes (ADR §3), so
    // non-exportability must come from the Secure Enclave token. Machines
    // without a Secure Enclave fail closed here; no software fallback.
    var accessError: Unmanaged<CFError>?
    guard
      let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage],
        &accessError
      )
    else {
      _ = accessError?.takeRetainedValue()
      throw BridgeIdentityError.keyStoreFailure
    }
    let privateAttributes: [CFString: Any] = [
      kSecAttrIsPermanent: true,
      kSecAttrApplicationTag: namespace.keyTag(for: role),
      kSecAttrLabel: "CodexMicroBridgeIdentity",
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
      _ = error?.takeRetainedValue()
      throw BridgeIdentityError.keyStoreFailure
    }
    return SecureEnclaveIdentityKey(secKey: key)
  }

  public func existingKeys(for role: BridgeIdentityRole) throws -> [any SecureIdentityKey] {
    let query: [CFString: Any] = [
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrApplicationTag: namespace.keyTag(for: role),
      kSecMatchLimit: kSecMatchLimitAll,
      kSecReturnRef: true,
      kSecUseDataProtectionKeychain: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else { return [] }
    guard status == errSecSuccess, let keys = item as? [SecKey] else {
      throw BridgeIdentityError.keyStoreFailure
    }
    return keys.map(SecureEnclaveIdentityKey.init(secKey:))
  }

  public func deleteKey(_ key: any SecureIdentityKey, for role: BridgeIdentityRole) throws {
    guard let enclaveKey = key as? SecureEnclaveIdentityKey else {
      throw BridgeIdentityError.keyStoreFailure
    }
    let query: [CFString: Any] = [
      kSecClass: kSecClassKey,
      kSecValueRef: enclaveKey.secKey,
      kSecUseDataProtectionKeychain: true,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw BridgeIdentityError.keyStoreFailure
    }
  }

  public func deleteAllKeys(for role: BridgeIdentityRole) throws {
    let query: [CFString: Any] = [
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecAttrApplicationTag: namespace.keyTag(for: role),
      kSecUseDataProtectionKeychain: true,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw BridgeIdentityError.keyStoreFailure
    }
  }

  public func withExclusiveCreation<T>(_ body: () throws -> T) rethrows -> T {
    Self.creationLock.lock()
    defer { Self.creationLock.unlock() }
    return try body()
  }

  private func claimQuery(for role: BridgeIdentityRole) -> [CFString: Any] {
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: namespace.claimServiceName,
      kSecAttrAccount: namespace.claimAccount(for: role),
      kSecUseDataProtectionKeychain: true,
    ]
  }
}
