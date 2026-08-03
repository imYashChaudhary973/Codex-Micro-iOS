import CompanionCrypto
import Foundation
import Security

/// The phone's long-term identity, held in the Secure Enclave.
///
/// **The private key is generated in the Enclave and never leaves it.** The
/// key is created with `kSecAttrTokenIDSecureEnclave` and signing goes through
/// `SecKeyCreateSignature`, so no code path — including this one — can read the
/// private bytes. That is the property acceptance case 1 exists to check.
///
/// Accessibility is `WhenUnlockedThisDeviceOnly`: the key is unusable before
/// first unlock, never leaves this device, and is not carried into an
/// encrypted backup. A rebooted, still-locked phone therefore fails to
/// authenticate rather than authenticating from a cached credential, which is
/// what acceptance case 7 checks.
///
/// **A missing key is never silently replaced.** ``load()`` returns `nil` and
/// the caller must decide; only ``create()`` mints one. A reinstall that
/// quietly generated a fresh key would invalidate the Mac's grant while
/// looking like it worked, which is exactly the failure case 1 watches for.
public enum DeviceIdentity {
  /// Keychain label for the device identity key.
  static let tag = Data("com.codexmicro.acceptance.device-identity".utf8)

  public enum Failure: Error, Equatable, Sendable {
    case enclaveUnavailable
    case keyUnreadable
    case signatureFailed
    case alreadyExists
  }

  /// The stored key, or `nil` when none exists.
  public static func load() throws -> SecKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
      guard let item else { throw Failure.keyUnreadable }
      return (item as! SecKey)
    case errSecItemNotFound:
      return nil
    default:
      throw Failure.keyUnreadable
    }
  }

  /// Creates the identity. Refuses to overwrite an existing one.
  public static func create() throws -> SecKey {
    guard try load() == nil else { throw Failure.alreadyExists }
    var accessError: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        &accessError
      )
    else {
      throw Failure.enclaveUnavailable
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access,
      ],
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw Failure.enclaveUnavailable
    }
    return key
  }

  /// Destroys the identity. Used only by the reinstall acceptance case.
  public static func destroy() throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw Failure.keyUnreadable
    }
  }

  /// The 65-byte X9.63 public key the Mac stores in the grant.
  public static func publicKeyX963(_ key: SecKey) throws -> Data {
    guard let publicKey = SecKeyCopyPublicKey(key),
      let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?
    else {
      throw Failure.keyUnreadable
    }
    return data
  }
}

/// Signs pairing transcripts with the Enclave key.
///
/// The seam returns exactly 64 raw `r||s` bytes, but the Enclave produces a
/// DER-encoded ECDSA signature, so the conversion happens here — and it is a
/// conversion, not a re-signing: the same signature is simply re-encoded.
/// `SecKey` is thread-safe for signing but not marked `Sendable` by the SDK,
/// so the unchecked conformance asserts exactly that and nothing more.
public struct EnclaveTranscriptSigner: PairingTranscriptSigner, @unchecked Sendable {
  private let key: SecKey

  public init(key: SecKey) {
    self.key = key
  }

  public func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    var error: Unmanaged<CFError>?
    guard
      let der = SecKeyCreateSignature(
        key,
        .ecdsaSignatureMessageX962SHA256,
        canonicalBytes as CFData,
        &error
      ) as Data?
    else {
      throw DeviceIdentity.Failure.signatureFailed
    }
    return try Self.rawSignature(fromDER: der)
  }

  /// Converts a DER `SEQUENCE { INTEGER r, INTEGER s }` into fixed 32-byte
  /// `r||s`.
  ///
  /// DER integers are signed and minimally encoded, so `r` and `s` arrive with
  /// a leading zero when their high bit is set and *without* leading zeros
  /// otherwise. Both cases must be normalised to exactly 32 bytes; getting
  /// this wrong produces a signature that verifies only about half the time,
  /// which is the kind of defect that looks like a flaky network.
  static func rawSignature(fromDER der: Data) throws -> Data {
    var index = 0
    let bytes = [UInt8](der)

    func read(_ expectedTag: UInt8) throws -> Int {
      guard index < bytes.count, bytes[index] == expectedTag else {
        throw DeviceIdentity.Failure.signatureFailed
      }
      index += 1
      guard index < bytes.count else { throw DeviceIdentity.Failure.signatureFailed }
      let first = bytes[index]
      index += 1
      if first & 0x80 == 0 { return Int(first) }
      let count = Int(first & 0x7F)
      guard count > 0, count <= 2, index + count <= bytes.count else {
        throw DeviceIdentity.Failure.signatureFailed
      }
      var length = 0
      for _ in 0..<count {
        length = (length << 8) | Int(bytes[index])
        index += 1
      }
      return length
    }

    func readInteger() throws -> [UInt8] {
      let length = try read(0x02)
      guard index + length <= bytes.count else { throw DeviceIdentity.Failure.signatureFailed }
      var value = Array(bytes[index..<(index + length)])
      index += length
      while value.first == 0x00, value.count > 1 { value.removeFirst() }
      guard value.count <= 32 else { throw DeviceIdentity.Failure.signatureFailed }
      return Array(repeating: 0, count: 32 - value.count) + value
    }

    _ = try read(0x30)
    let r = try readInteger()
    let s = try readInteger()
    return Data(r + s)
  }
}
