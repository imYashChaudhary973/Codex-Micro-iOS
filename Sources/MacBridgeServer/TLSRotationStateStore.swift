import Darwin
import Foundation

/// Closed rotation-state failure vocabulary. Carries no content.
public enum TLSRotationStateError: Error, Equatable, Sendable {
  /// The persisted blob is malformed, truncated, oversized, carries an
  /// unknown version or domain, or has trailing bytes. Fails closed.
  case corruptState
  /// The next rotation generation would overflow; the authority is
  /// disabled instead of wrapping (ADR §11).
  case generationOverflow
  /// The live TLS identity no longer matches the recorded current SPKI.
  /// Callers must treat this as identity loss and disable LAN.
  case identityLost
  /// Rotation state already exists; the baseline is written exactly once.
  case stateAlreadyInitialized
  /// No rotation state exists yet for the requested operation.
  case stateMissing
  /// Reading or writing the persistent store failed. Fails closed; no
  /// memory-only fallback.
  case storageUnavailable
  /// The operation requires the `.host` identity role.
  case wrongIdentityRole
}

/// Persistent anti-rollback rotation record (ADR §7).
///
/// Generation `0` is the pre-rotation baseline recorded when the first TLS
/// identity is created; every accepted rotation strictly increases the
/// generation and shifts the SPKI pair.
public struct TLSRotationState: Equatable, Sendable {
  /// Monotonic rotation generation; `0` is the baseline.
  public let rotationGeneration: UInt64
  /// SHA-256 SPKI fingerprint of the currently pinned TLS key.
  public let currentSPKIFingerprint: Data
  /// The previously pinned fingerprint; `nil` exactly at the baseline.
  public let previousSPKIFingerprint: Data?

  /// Creates a validated state record. Fingerprints must be exactly 32
  /// bytes and the previous fingerprint is present iff the generation is
  /// past the baseline.
  public init(
    rotationGeneration: UInt64,
    currentSPKIFingerprint: Data,
    previousSPKIFingerprint: Data?
  ) throws {
    guard currentSPKIFingerprint.count == 32 else {
      throw TLSRotationStateError.corruptState
    }
    if let previousSPKIFingerprint {
      guard previousSPKIFingerprint.count == 32,
        rotationGeneration >= 1,
        previousSPKIFingerprint != currentSPKIFingerprint
      else {
        throw TLSRotationStateError.corruptState
      }
    } else {
      guard rotationGeneration == 0 else {
        throw TLSRotationStateError.corruptState
      }
    }
    self.rotationGeneration = rotationGeneration
    self.currentSPKIFingerprint = currentSPKIFingerprint
    self.previousSPKIFingerprint = previousSPKIFingerprint
  }
}

/// Versioned canonical blob codec for ``TLSRotationState``.
///
/// Follows the ADR §11 canonical pattern: leading version byte, a
/// length-prefixed ASCII domain separator unique to this record type,
/// fixed-width big-endian integers, `UInt16` length prefixes, an explicit
/// presence byte for the optional field, and no trailing bytes. Any
/// violation decodes as ``TLSRotationStateError/corruptState``.
enum TLSRotationStateBlobCodec {
  static let version: UInt8 = 1
  static let domain = "codex-micro/tls-rotation-state/v1"
  static let maximumBlobByteCount = 256

  static func encode(_ state: TLSRotationState) -> Data {
    var blob = Data()
    blob.append(version)
    appendVariableBytes(Data(domain.utf8), to: &blob)
    appendUInt64(state.rotationGeneration, to: &blob)
    appendVariableBytes(state.currentSPKIFingerprint, to: &blob)
    if let previous = state.previousSPKIFingerprint {
      blob.append(1)
      appendVariableBytes(previous, to: &blob)
    } else {
      blob.append(0)
    }
    return blob
  }

  static func decode(_ blob: Data) throws -> TLSRotationState {
    guard blob.count <= maximumBlobByteCount else {
      throw TLSRotationStateError.corruptState
    }
    var reader = BlobReader(blob)
    guard try reader.readByte() == version,
      try reader.readVariableBytes() == Data(domain.utf8)
    else {
      throw TLSRotationStateError.corruptState
    }
    let generation = try reader.readUInt64()
    let current = try reader.readVariableBytes()
    let previous: Data?
    switch try reader.readByte() {
    case 0:
      previous = nil
    case 1:
      previous = try reader.readVariableBytes()
    default:
      throw TLSRotationStateError.corruptState
    }
    try reader.requireEnd()
    return try TLSRotationState(
      rotationGeneration: generation,
      currentSPKIFingerprint: current,
      previousSPKIFingerprint: previous
    )
  }

  private static func appendUInt64(_ value: UInt64, to blob: inout Data) {
    withUnsafeBytes(of: value.bigEndian) { blob.append(contentsOf: $0) }
  }

  private static func appendVariableBytes(_ data: Data, to blob: inout Data) {
    withUnsafeBytes(of: UInt16(data.count).bigEndian) { blob.append(contentsOf: $0) }
    blob.append(data)
  }

  private struct BlobReader {
    private let bytes: Data
    private var offset = 0

    init(_ blob: Data) {
      bytes = Data(blob)
    }

    mutating func readByte() throws -> UInt8 {
      try take(1)[0]
    }

    mutating func readUInt64() throws -> UInt64 {
      try take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    mutating func readVariableBytes() throws -> Data {
      let count = Int(try take(2).reduce(UInt16(0)) { ($0 << 8) | UInt16($1) })
      return try take(count)
    }

    func requireEnd() throws {
      guard offset == bytes.count else {
        throw TLSRotationStateError.corruptState
      }
    }

    private mutating func take(_ count: Int) throws -> Data {
      guard bytes.count - offset >= count else {
        throw TLSRotationStateError.corruptState
      }
      defer { offset += count }
      return bytes.subdata(in: offset..<(offset + count))
    }
  }
}

/// Byte-level persistence seam for rotation state.
///
/// The production implementation is ``FileBackedRotationStateStore``;
/// tests inject a deterministic in-memory store with failure hooks.
/// Implementations throw only ``TLSRotationStateError`` cases.
public protocol TLSRotationStateStorage {
  /// The persisted blob, or `nil` when no state has ever been written.
  func readBlob() throws -> Data?

  /// Atomically replaces the persisted blob.
  func writeBlob(_ blob: Data) throws
}

/// File-backed rotation-state storage under Application Support.
///
/// Follows the `PersistentCommandLedger` file-protection pattern: a
/// `0700` parent directory, `0600` file permissions, and backup
/// exclusion. Writes are atomic whole-blob replacements. The blob content
/// is non-secret (generation and public-key fingerprints) but its
/// integrity is anti-rollback state, so reads are strictly bounded and
/// every filesystem failure maps to a closed error.
public struct FileBackedRotationStateStore: TLSRotationStateStorage {
  private static let fileName = "tls-rotation-state.v1.bin"

  private let fileURL: URL

  /// Creates a store inside `directoryURL`, creating the directory with
  /// `0700` permissions when needed.
  public init(directoryURL: URL) throws {
    do {
      try FileManager.default.createDirectory(
        at: directoryURL,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    } catch {
      throw TLSRotationStateError.storageUnavailable
    }
    self.fileURL = directoryURL.appendingPathComponent(Self.fileName, isDirectory: false)
  }

  /// Creates the production store under
  /// `Application Support/CodexMicro/BridgeServer`.
  public static func applicationSupport() throws -> FileBackedRotationStateStore {
    guard
      let base = FileManager.default.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
      ).first
    else {
      throw TLSRotationStateError.storageUnavailable
    }
    let directory =
      base
      .appendingPathComponent("CodexMicro", isDirectory: true)
      .appendingPathComponent("BridgeServer", isDirectory: true)
    return try FileBackedRotationStateStore(directoryURL: directory)
  }

  public func readBlob() throws -> Data? {
    guard FileManager.default.fileExists(atPath: fileURL.path) else {
      return nil
    }
    guard let blob = try? Data(contentsOf: fileURL) else {
      throw TLSRotationStateError.storageUnavailable
    }
    guard blob.count <= TLSRotationStateBlobCodec.maximumBlobByteCount else {
      throw TLSRotationStateError.corruptState
    }
    return blob
  }

  public func writeBlob(_ blob: Data) throws {
    do {
      try blob.write(to: fileURL, options: [.atomic])
    } catch {
      throw TLSRotationStateError.storageUnavailable
    }
    guard chmod(fileURL.path, S_IRUSR | S_IWUSR) == 0 else {
      throw TLSRotationStateError.storageUnavailable
    }
    do {
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      var mutableURL = fileURL
      try mutableURL.setResourceValues(values)
    } catch {
      throw TLSRotationStateError.storageUnavailable
    }
  }
}
