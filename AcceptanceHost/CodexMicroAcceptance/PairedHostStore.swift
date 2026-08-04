import CompanionCrypto
import CompanionProtocol
import Foundation
import Security

/// What the phone must remember about a paired Mac to ever reconnect to it.
///
/// Pairing establishes four facts and, until now, the phone discarded all of
/// them the moment the socket closed: it could pair and never connect again.
///
/// Each field is a pin, not a convenience:
///
/// - `hostID` identifies which Mac this is.
/// - `hostPublicKeyX963` is **the only key a host reply is ever verified
///   against**. Losing it and re-learning it from the network would defeat
///   pairing entirely.
/// - `tlsSPKIFingerprint` is what the TLS layer pins. It changes only through
///   a host-signed rotation statement, never because a server presented
///   something else.
/// - `endpointOrigin` is where to look. It is the one field that may be
///   wrong without being dangerous — a moved Mac fails to connect, and the
///   pins ensure a *different* Mac at that address fails too.
public struct PairedHost: Codable, Equatable, Sendable {
  public let hostID: UUID
  public let hostPublicKeyX963: Data
  public let tlsSPKIFingerprint: Data
  public let endpointOrigin: String

  public init(
    hostID: UUID,
    hostPublicKeyX963: Data,
    tlsSPKIFingerprint: Data,
    endpointOrigin: String
  ) {
    self.hostID = hostID
    self.hostPublicKeyX963 = hostPublicKeyX963
    self.tlsSPKIFingerprint = tlsSPKIFingerprint
    self.endpointOrigin = endpointOrigin
  }

  /// Records what the QR carried once pairing has completed.
  ///
  /// The host public key comes from the verified response rather than the QR,
  /// because the QR carries only a *fingerprint* of it — and a fingerprint
  /// cannot verify a signature.
  public init(payload: PairingQRPayload, hostPublicKeyX963: Data) {
    self.hostID = payload.hostID
    self.hostPublicKeyX963 = hostPublicKeyX963
    self.tlsSPKIFingerprint = payload.tlsSPKIFingerprint
    self.endpointOrigin = payload.endpointOrigin.normalized
  }
}

/// Stores the paired host in the Keychain.
///
/// **This is pinning material, not a preference.** `UserDefaults` would put
/// the only key that authenticates the Mac into a plist any process with the
/// container can rewrite. It is stored `WhenUnlockedThisDeviceOnly` for the
/// same reason as the device identity: unusable before first unlock, never
/// leaves the device, never enters a backup.
public enum PairedHostStore {
  private static let service = "com.codexmicro.acceptance.paired-host"
  private static let account = "host-v1"

  public enum Failure: Error, Equatable, Sendable {
    case writeFailed
    case readFailed
    case corrupt
  }

  public static func save(_ host: PairedHost) throws {
    let data = try JSONEncoder().encode(host)
    // Delete-then-add rather than update: the attribute set is small and
    // fixed, and a partial update that left the old accessibility class would
    // be invisible until the first locked-device read failed.
    SecItemDelete(baseQuery as CFDictionary)
    var attributes = baseQuery
    attributes[kSecValueData as String] = data
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else {
      throw Failure.writeFailed
    }
  }

  /// The stored host, or `nil` when this phone has never paired.
  public static func load() throws -> PairedHost? {
    var query = baseQuery
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    switch SecItemCopyMatching(query as CFDictionary, &item) {
    case errSecSuccess:
      guard let data = item as? Data else { throw Failure.readFailed }
      // A stored record that will not decode is corrupt, not absent.
      // Returning nil would silently offer to pair again and orphan the
      // grant the Mac still holds.
      guard let host = try? JSONDecoder().decode(PairedHost.self, from: data) else {
        throw Failure.corrupt
      }
      return host
    case errSecItemNotFound:
      return nil
    default:
      throw Failure.readFailed
    }
  }

  /// Forgets the paired host. Used when the user unpairs.
  public static func clear() throws {
    let status = SecItemDelete(baseQuery as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw Failure.writeFailed
    }
  }

  private static var baseQuery: [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecUseDataProtectionKeychain as String: true,
      kSecAttrSynchronizable as String: false,
    ]
  }
}
