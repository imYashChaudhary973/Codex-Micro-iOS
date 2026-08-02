import CryptoKit
import Foundation
import X509

@testable import MacBridgeServer

/// Deterministic in-memory stand-in for a Secure Enclave key: a software
/// CryptoKit P-256 key wrapped behind the production `SecureIdentityKey`
/// seam, with injectable attribute/export/lookup failures.
final class FakeSecureIdentityKey: SecureIdentityKey {
  let privateKey: P256.Signing.PrivateKey
  var attributesValid = true
  var exportable = false
  var publicKeyAvailable = true
  var signingFails = false

  init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
    self.privateKey = privateKey
  }

  func publicKeyX963() throws -> Data {
    guard publicKeyAvailable else {
      throw BridgeIdentityError.publicKeyUnavailable
    }
    return privateKey.publicKey.x963Representation
  }

  func signRaw(_ message: Data) throws -> Data {
    guard !signingFails else {
      throw BridgeIdentityError.signatureFailure
    }
    return try privateKey.signature(for: message).rawRepresentation
  }

  func validateRequiredAttributes() throws {
    guard attributesValid else {
      throw BridgeIdentityError.attributeMismatch
    }
  }

  func assertNonExportable() throws {
    guard !exportable else {
      throw BridgeIdentityError.privateKeyExportable
    }
  }

  func certificateSigner() throws -> Certificate.PrivateKey {
    Certificate.PrivateKey(privateKey)
  }
}

/// Deterministic in-memory `SecureIdentityBackend` with injectable
/// failures for every operation, so the production store logic (claims,
/// rollback, validation ordering, fail-closed behavior) is exercised
/// without entitlements.
final class FakeSecureIdentityBackend: SecureIdentityBackend {
  var claims: [BridgeIdentityRole: Int] = [:]
  var keys: [BridgeIdentityRole: [FakeSecureIdentityKey]] = [:]

  var insertClaimError: BridgeIdentityError?
  var claimCountError: BridgeIdentityError?
  var removeClaimError: BridgeIdentityError?
  var createKeyError: BridgeIdentityError?
  var existingKeysError: BridgeIdentityError?
  var deleteKeyError: BridgeIdentityError?
  var deleteAllKeysError: BridgeIdentityError?
  /// When set, `deleteAllKeys` reports success but leaves keys behind,
  /// modeling a cleanup that silently fails verification.
  var deleteAllKeysSilentlyFails = false

  /// Factory for the next created key (deterministic or corrupt keys).
  var nextCreatedKey: (() -> FakeSecureIdentityKey)?
  /// Runs right after key creation, before post-create validation.
  var afterCreateKey: ((FakeSecureIdentityBackend) -> Void)?

  func insertClaim(for role: BridgeIdentityRole) throws -> BridgeClaimInsertion {
    if let insertClaimError { throw insertClaimError }
    guard claims[role, default: 0] == 0 else { return .alreadyPresent }
    claims[role] = 1
    return .inserted
  }

  func claimCount(for role: BridgeIdentityRole) throws -> Int {
    if let claimCountError { throw claimCountError }
    return claims[role, default: 0]
  }

  func removeClaim(for role: BridgeIdentityRole) throws {
    if let removeClaimError { throw removeClaimError }
    claims[role] = 0
  }

  func createKey(for role: BridgeIdentityRole) throws -> any SecureIdentityKey {
    if let createKeyError { throw createKeyError }
    let key = nextCreatedKey?() ?? FakeSecureIdentityKey()
    keys[role, default: []].append(key)
    afterCreateKey?(self)
    return key
  }

  func existingKeys(for role: BridgeIdentityRole) throws -> [any SecureIdentityKey] {
    if let existingKeysError { throw existingKeysError }
    return keys[role, default: []]
  }

  func deleteKey(_ key: any SecureIdentityKey, for role: BridgeIdentityRole) throws {
    if let deleteKeyError { throw deleteKeyError }
    keys[role, default: []].removeAll { $0 === (key as? FakeSecureIdentityKey) }
  }

  func deleteAllKeys(for role: BridgeIdentityRole) throws {
    if let deleteAllKeysError { throw deleteAllKeysError }
    guard !deleteAllKeysSilentlyFails else { return }
    keys[role] = []
  }

  func withExclusiveCreation<T>(_ body: () throws -> T) rethrows -> T {
    try body()
  }
}

/// Shared deterministic fixtures for MacBridgeServer tests.
enum ServerTestFixtures {
  /// Fixed software P-256 key so signatures verify against a stable
  /// public key across tests.
  static let hostPrivateKeyRaw = Data([
    0x6F, 0x2A, 0x51, 0x1C, 0x0E, 0x51, 0x1A, 0x63, 0x25, 0x1E, 0x3A, 0x40,
    0x62, 0x2E, 0x1B, 0x2D, 0x5C, 0x24, 0x69, 0x0F, 0x2C, 0x4E, 0x5B, 0x1F,
    0x3D, 0x30, 0x7A, 0x18, 0x2B, 0x66, 0x4D, 0x21,
  ])

  /// A second fixed software P-256 key for distinct-key scenarios.
  static let tlsPrivateKeyRaw = Data([
    0x21, 0x4D, 0x66, 0x2B, 0x18, 0x7A, 0x30, 0x3D, 0x1F, 0x5B, 0x4E, 0x2C,
    0x0F, 0x69, 0x24, 0x5C, 0x2D, 0x1B, 0x2E, 0x62, 0x40, 0x3A, 0x1E, 0x25,
    0x63, 0x1A, 0x51, 0x0E, 0x1C, 0x51, 0x2A, 0x6F,
  ])

  static func hostKey() -> P256.Signing.PrivateKey {
    try! P256.Signing.PrivateKey(rawRepresentation: hostPrivateKeyRaw)
  }

  static func tlsKey() -> P256.Signing.PrivateKey {
    try! P256.Signing.PrivateKey(rawRepresentation: tlsPrivateKeyRaw)
  }

  /// A store over `backend` whose reset policy always permits (no grants).
  static func store(
    backend: FakeSecureIdentityBackend,
    resetPermitted: Bool = true
  ) -> BridgeIdentityStore {
    BridgeIdentityStore(backend: backend, resetPolicy: { resetPermitted })
  }

  /// A loaded `.host` identity over the fixed host key.
  static func hostIdentity(
    backend: FakeSecureIdentityBackend = FakeSecureIdentityBackend()
  ) throws -> BridgeIdentity {
    backend.nextCreatedKey = { FakeSecureIdentityKey(privateKey: hostKey()) }
    return try store(backend: backend).create(role: .host)
  }

  /// A loaded `.tls` identity over the fixed TLS key.
  static func tlsIdentity(
    backend: FakeSecureIdentityBackend = FakeSecureIdentityBackend()
  ) throws -> BridgeIdentity {
    backend.nextCreatedKey = { FakeSecureIdentityKey(privateKey: tlsKey()) }
    return try store(backend: backend).create(role: .tls)
  }
}
