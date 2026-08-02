import Foundation
import Security

/// Result of loading the persisted authority blob.
public enum GrantAuthorityLoadResult: Equatable, Sendable {
  /// Exactly one explicit zero-byte fresh-install marker exists. This is
  /// the valid-empty authority state, distinct from a missing Keychain
  /// item, which throws ``DeviceGrantAuthorityError/authorityMissing``.
  case empty
  /// The store holds exactly one nonempty authority blob.
  case blob(Data)
}

/// Synchronous byte-level persistence seam for device-grant authority.
///
/// Exactly one ``DeviceGrantAuthority`` actor owns a store instance; the
/// blob is always loaded and replaced whole (ADR §10 atomic whole-blob
/// replacement). Methods are intentionally synchronous because the actor
/// loads during initialization before asynchronous session startup. A
/// conforming implementation must therefore be thread-safe and must not
/// require actor/async isolation. The authority actor serializes production
/// use; test fakes may also be inspected concurrently. Implementations
/// throw only ``DeviceGrantAuthorityError`` cases.
public protocol GrantAuthorityStorage: Sendable {
  /// Loads the explicit-empty marker or the persisted blob. A missing item
  /// is an error, never an implicit fresh install.
  func load() throws -> GrantAuthorityLoadResult

  /// Atomically replaces the persisted value as one whole Keychain item.
  /// Passing empty data is reserved for explicit first-install
  /// provisioning before ``DeviceGrantAuthority`` is constructed.
  func replace(blob: Data) throws
}

/// Production grant-authority storage in the device-only Data Protection
/// Keychain (ADR §10).
///
/// The value lives as a single generic password item under one fixed
/// service/account pair with `kSecUseDataProtectionKeychain`,
/// `AfterFirstUnlockThisDeviceOnly` accessibility, and no synchronization,
/// so it never syncs or leaves the device. Loading matches all candidate
/// items and fails closed on absence or duplicates. Replacement uses one
/// `SecItemAdd` or `SecItemUpdate` whole-value write; the duplicate path
/// verifies exact cardinality before updating and verifies the exact value
/// afterward, so an unexpected duplicate/race fails closed rather than
/// updating an unverified item set. Security.framework operations are
/// synchronous and thread-safe. `OSStatus` values never leave this type.
public struct DataProtectionKeychainGrantStore: GrantAuthorityStorage {
  private static let service = "com.codexmicro.device-grant-authority"
  private static let account = "authority-blob-v1"

  /// Creates the store over the fixed production service/account item.
  public init() {}

  public func load() throws -> GrantAuthorityLoadResult {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
      kSecUseDataProtectionKeychain as String: true,
      kSecAttrSynchronizable as String: false,
      kSecReturnData as String: true,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      throw DeviceGrantAuthorityError.authorityMissing
    }
    guard status == errSecSuccess, let items = result as? [[String: Any]] else {
      throw DeviceGrantAuthorityError.storageUnavailable
    }
    guard items.count == 1, let item = items.first else {
      throw DeviceGrantAuthorityError.duplicateAuthorityItem
    }
    guard let value = item[kSecValueData as String] as? Data,
      item[kSecAttrAccessible as String] as? String
        == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String,
      item[kSecAttrSynchronizable as String] as? Bool == false
    else {
      throw DeviceGrantAuthorityError.storageUnavailable
    }
    if value.isEmpty {
      return .empty
    }
    guard value.count <= GrantAuthorityLimits.maximumBlobByteCount else {
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    return .blob(value)
  }

  public func replace(blob: Data) throws {
    guard blob.count <= GrantAuthorityLimits.maximumBlobByteCount else {
      throw DeviceGrantAuthorityError.authorityOversized
    }
    let addQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
      kSecUseDataProtectionKeychain as String: true,
      kSecAttrSynchronizable as String: false,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecValueData as String: blob,
    ]
    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    if addStatus == errSecSuccess {
      // Only explicit first-install provisioning may create the item. If a
      // mutation discovers the item missing, remove the unexpected write and
      // surface authority loss instead of silently recreating continuity.
      guard blob.isEmpty else {
        let cleanupStatus = SecItemDelete(itemQuery as CFDictionary)
        guard cleanupStatus == errSecSuccess || cleanupStatus == errSecItemNotFound else {
          throw DeviceGrantAuthorityError.storageUnavailable
        }
        throw DeviceGrantAuthorityError.authorityMissing
      }
      try verifyPersistedValue(blob)
      return
    }
    guard addStatus == errSecDuplicateItem else {
      throw DeviceGrantAuthorityError.storageUnavailable
    }

    // Fail closed unless the duplicate represents exactly one correctly
    // protected item. The same attributes remain in the update predicate so
    // a replacement race cannot redirect the write to a weaker item.
    _ = try load()
    let updateQuery = itemQuery
    let update: [String: Any] = [
      kSecValueData as String: blob
    ]
    let updateStatus = SecItemUpdate(updateQuery as CFDictionary, update as CFDictionary)
    guard updateStatus == errSecSuccess else {
      throw DeviceGrantAuthorityError.storageUnavailable
    }
    try verifyPersistedValue(blob)
  }

  private var itemQuery: [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: Self.account,
      kSecUseDataProtectionKeychain as String: true,
      kSecAttrSynchronizable as String: false,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
  }

  private func verifyPersistedValue(_ expected: Data) throws {
    switch try load() {
    case .empty:
      guard expected.isEmpty else {
        throw DeviceGrantAuthorityError.storageUnavailable
      }
    case .blob(let actual):
      guard actual == expected else {
        throw DeviceGrantAuthorityError.storageUnavailable
      }
    }
  }
}
