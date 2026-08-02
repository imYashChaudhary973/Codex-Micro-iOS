import CompanionProtocol
import CryptoKit
import Foundation

/// The two application-frame directions. Each direction owns a distinct
/// 4-byte ASCII wire prefix that appears once in the clear header and as the
/// leading 4 bytes of the deterministic 96-bit AEAD nonce (ADR §11).
public enum SecureFrameDirection: CaseIterable, Equatable, Sendable {
  case clientToServer
  case serverToClient

  /// The 4-byte direction/domain prefix (`"c2s1"` / `"s2c1"`).
  public var wirePrefix: Data {
    switch self {
    case .clientToServer: Data([0x63, 0x32, 0x73, 0x31])
    case .serverToClient: Data([0x73, 0x32, 0x63, 0x31])
    }
  }

  init?(wirePrefix: Data) {
    guard let match = Self.allCases.first(where: { $0.wirePrefix == wirePrefix }) else {
      return nil
    }
    self = match
  }
}

/// Closed frame-codec failure vocabulary; carries no frame content. Any
/// failure closes the affected sealer/opener permanently — the session is
/// over and requires a fresh handshake with fresh keys.
public enum SecureFrameError: Error, Equatable, Sendable {
  case invalidKeyLength
  case invalidVersion
  case invalidDirection
  case invalidLength
  case invalidPlaintextLength
  case connectionMismatch
  case duplicateCounter
  case counterGap
  case counterExhausted
  case authenticationFailed
  case sealingFailed
  case sessionClosed
}

/// Clear header of one sealed application frame. The complete encoded header
/// is authenticated as AEAD additional data; nothing in it is malleable.
///
/// Fixed 33-byte layout: version (1) || direction prefix (4) ||
/// connectionID (16) || big-endian counter (8) || big-endian ciphertext
/// length (4). The ciphertext length excludes the 16-byte Poly1305 tag.
public struct SecureFrameHeader: Equatable, Sendable {
  /// Exact encoded header byte count.
  public static let headerByteCount = 33
  /// Exact Poly1305 tag byte count.
  public static let tagByteCount = 16
  /// The only frame version this build produces or accepts.
  public static let currentVersion: UInt8 = 1
  /// Highest counter either side may ever use. `UInt64.max` is reserved as
  /// the overflow sentinel, so the codec fails closed before any wrap.
  public static let maxCounter: UInt64 = .max - 1
  /// Maximum plaintext bytes so a sealed frame fits one WebSocket message.
  public static let maxPlaintextByteCount =
    SecureTransportLimits.maxMessageBytes - headerByteCount - tagByteCount

  public let connectionID: UUID
  public let direction: SecureFrameDirection
  public let counter: UInt64
  public let ciphertextLength: UInt32

  public init(
    connectionID: UUID,
    direction: SecureFrameDirection,
    counter: UInt64,
    ciphertextLength: UInt32
  ) {
    self.connectionID = connectionID
    self.direction = direction
    self.counter = counter
    self.ciphertextLength = ciphertextLength
  }

  /// The exact 33-byte encoded header; the AEAD additional data.
  public func encoded() -> Data {
    var bytes = Data(capacity: Self.headerByteCount)
    bytes.append(Self.currentVersion)
    bytes.append(direction.wirePrefix)
    bytes.append(Data(uuid: connectionID))
    withUnsafeBytes(of: counter.bigEndian) { bytes.append(contentsOf: $0) }
    withUnsafeBytes(of: ciphertextLength.bigEndian) { bytes.append(contentsOf: $0) }
    return bytes
  }

  /// Strictly decodes the clear header of a received frame. Short input,
  /// wrong version, and unknown direction prefixes fail closed.
  public static func decode(fromFrame frame: Data) throws -> SecureFrameHeader {
    let bytes = Data(frame)
    guard bytes.count >= headerByteCount else {
      throw SecureFrameError.invalidLength
    }
    guard bytes[0] == currentVersion else {
      throw SecureFrameError.invalidVersion
    }
    guard let direction = SecureFrameDirection(wirePrefix: bytes.subdata(in: 1..<5)) else {
      throw SecureFrameError.invalidDirection
    }
    let connectionID = UUID(canonicalBytes: bytes.subdata(in: 5..<21))
    let counter = bytes.subdata(in: 21..<29).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    let length = bytes.subdata(in: 29..<33).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    return SecureFrameHeader(
      connectionID: connectionID,
      direction: direction,
      counter: counter,
      ciphertextLength: length
    )
  }

  /// Deterministic 96-bit AEAD nonce: the 4-byte direction prefix followed by
  /// the 8-byte big-endian counter. Injective per key because every direction
  /// of every session uses a fresh key and counters never wrap.
  static func nonceBytes(direction: SecureFrameDirection, counter: UInt64) -> Data {
    var bytes = direction.wirePrefix
    withUnsafeBytes(of: counter.bigEndian) { bytes.append(contentsOf: $0) }
    return bytes
  }
}

/// Seals outbound application frames for one direction of one connection
/// with ChaCha20-Poly1305. Counters start at 0 and increment by exactly one;
/// the sealer refuses to seal past `SecureFrameHeader.maxCounter` and fails
/// closed permanently on any error.
public struct SecureFrameSealer: Sendable {
  private let key: SymmetricKey
  private let connectionID: UUID
  private let direction: SecureFrameDirection
  private var nextCounter: UInt64
  private var isClosed = false

  public init(key: SymmetricKey, connectionID: UUID, direction: SecureFrameDirection) throws {
    try self.init(key: key, connectionID: connectionID, direction: direction, nextCounter: 0)
  }

  init(
    key: SymmetricKey,
    connectionID: UUID,
    direction: SecureFrameDirection,
    nextCounter: UInt64
  ) throws {
    guard key.bitCount == SecureSessionKeySchedule.frameKeyByteCount * 8 else {
      throw SecureFrameError.invalidKeyLength
    }
    self.key = key
    self.connectionID = connectionID
    self.direction = direction
    self.nextCounter = nextCounter
  }

  /// Seals one plaintext into `header || ciphertext || tag`, authenticating
  /// the entire clear header as additional data.
  public mutating func seal(_ plaintext: Data) throws -> Data {
    guard !isClosed else {
      throw SecureFrameError.sessionClosed
    }
    do {
      return try sealNext(plaintext)
    } catch {
      isClosed = true
      throw error
    }
  }

  private mutating func sealNext(_ plaintext: Data) throws -> Data {
    guard (1...SecureFrameHeader.maxPlaintextByteCount).contains(plaintext.count) else {
      throw SecureFrameError.invalidPlaintextLength
    }
    guard nextCounter <= SecureFrameHeader.maxCounter else {
      throw SecureFrameError.counterExhausted
    }
    let header = SecureFrameHeader(
      connectionID: connectionID,
      direction: direction,
      counter: nextCounter,
      ciphertextLength: UInt32(plaintext.count)
    )
    let headerBytes = header.encoded()
    guard
      let nonce = try? ChaChaPoly.Nonce(
        data: SecureFrameHeader.nonceBytes(direction: direction, counter: nextCounter)),
      let box = try? ChaChaPoly.seal(
        plaintext, using: key, nonce: nonce, authenticating: headerBytes)
    else {
      throw SecureFrameError.sealingFailed
    }
    nextCounter += 1
    return headerBytes + box.ciphertext + box.tag
  }
}

/// Opens inbound application frames for one direction of one connection.
/// A receiver accepts exactly the next counter; any duplicate, gap,
/// reflection, cross-connection frame, tamper, truncation, or overflow is
/// rejected with a closed error and the opener fails closed permanently.
public struct SecureFrameOpener: Sendable {
  private let key: SymmetricKey
  private let connectionID: UUID
  private let direction: SecureFrameDirection
  private var expectedCounter: UInt64
  private var isClosed = false

  public init(key: SymmetricKey, connectionID: UUID, direction: SecureFrameDirection) throws {
    try self.init(key: key, connectionID: connectionID, direction: direction, expectedCounter: 0)
  }

  init(
    key: SymmetricKey,
    connectionID: UUID,
    direction: SecureFrameDirection,
    expectedCounter: UInt64
  ) throws {
    guard key.bitCount == SecureSessionKeySchedule.frameKeyByteCount * 8 else {
      throw SecureFrameError.invalidKeyLength
    }
    self.key = key
    self.connectionID = connectionID
    self.direction = direction
    self.expectedCounter = expectedCounter
  }

  /// Opens one received frame, returning its plaintext.
  public mutating func open(_ frame: Data) throws -> Data {
    guard !isClosed else {
      throw SecureFrameError.sessionClosed
    }
    do {
      return try openNext(frame)
    } catch {
      isClosed = true
      throw error
    }
  }

  private mutating func openNext(_ frame: Data) throws -> Data {
    let bytes = Data(frame)
    let header = try SecureFrameHeader.decode(fromFrame: bytes)
    guard header.direction == direction else {
      throw SecureFrameError.invalidDirection
    }
    guard header.connectionID == connectionID else {
      throw SecureFrameError.connectionMismatch
    }
    guard expectedCounter <= SecureFrameHeader.maxCounter, header.counter != .max else {
      throw SecureFrameError.counterExhausted
    }
    guard header.counter >= expectedCounter else {
      throw SecureFrameError.duplicateCounter
    }
    guard header.counter == expectedCounter else {
      throw SecureFrameError.counterGap
    }
    let ciphertextLength = Int(header.ciphertextLength)
    guard
      (1...SecureFrameHeader.maxPlaintextByteCount).contains(ciphertextLength),
      bytes.count
        == SecureFrameHeader.headerByteCount + ciphertextLength + SecureFrameHeader.tagByteCount
    else {
      throw SecureFrameError.invalidLength
    }
    let headerBytes = bytes.subdata(in: 0..<SecureFrameHeader.headerByteCount)
    let ciphertextEnd = SecureFrameHeader.headerByteCount + ciphertextLength
    let ciphertext = bytes.subdata(in: SecureFrameHeader.headerByteCount..<ciphertextEnd)
    let tag = bytes.subdata(in: ciphertextEnd..<bytes.count)
    guard
      let nonce = try? ChaChaPoly.Nonce(
        data: SecureFrameHeader.nonceBytes(direction: direction, counter: header.counter)),
      let box = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag),
      let plaintext = try? ChaChaPoly.open(box, using: key, authenticating: headerBytes)
    else {
      throw SecureFrameError.authenticationFailed
    }
    expectedCounter += 1
    return plaintext
  }
}
