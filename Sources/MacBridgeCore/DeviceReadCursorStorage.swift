import Foundation

/// Versioned canonical blob codec for ``DeviceReadCursorState`` (ADR §11).
///
/// Same canonical contract as the grant-authority blob: leading version byte,
/// length-prefixed ASCII domain separator unique to this record type,
/// fixed-width big-endian integers, `UInt16` length prefixes on variable
/// fields, strictly ascending device and thread ordering, and no trailing
/// bytes. Any violation decodes as
/// ``DeviceReadCursorError/corruptState``.
enum DeviceReadCursorBlobCodec {
  static let version: UInt8 = 1
  static let domain = "codex-micro/device-read-cursors/v1"

  static func encode(_ state: DeviceReadCursorState) throws -> Data {
    guard state.writeSequence >= 1,
      state.cursors.count <= DeviceReadCursorLimits.maxDevices
    else {
      throw DeviceReadCursorError.corruptState
    }

    var blob = Data()
    try append(byte: version, to: &blob)
    try append(variable: Data(domain.utf8), to: &blob)
    try append(uint64: state.writeSequence, to: &blob)

    let devices = state.cursors.keys.sorted {
      encoded($0).lexicographicallyPrecedes(encoded($1))
    }
    try append(count: devices.count, to: &blob)
    for deviceID in devices {
      let threads = state.cursors[deviceID] ?? [:]
      guard threads.count <= DeviceReadCursorLimits.maxThreadsPerDevice else {
        throw DeviceReadCursorError.cursorLimitExceeded
      }
      try append(bytes: encoded(deviceID), to: &blob)
      try append(count: threads.count, to: &blob)
      for threadID in threads.keys.sorted(by: {
        Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8))
      }) {
        guard let cursor = threads[threadID], cursor.deviceID == deviceID,
          cursor.threadID == threadID
        else {
          throw DeviceReadCursorError.corruptState
        }
        try append(variable: Data(threadID.utf8), to: &blob)
        try append(uint64: cursor.readSequence, to: &blob)
        try append(uint64: cursor.updatedAtEpochSeconds, to: &blob)
      }
    }
    return blob
  }

  static func decode(_ blob: Data) throws -> DeviceReadCursorState {
    guard blob.count <= DeviceReadCursorLimits.maximumBlobByteCount else {
      throw DeviceReadCursorError.corruptState
    }
    var reader = Reader(blob)
    guard try reader.byte() == version, try reader.variable() == Data(domain.utf8) else {
      throw DeviceReadCursorError.corruptState
    }
    let writeSequence = try reader.uint64()
    guard writeSequence >= 1 else {
      throw DeviceReadCursorError.corruptState
    }

    let deviceCount = Int(try reader.uint16())
    guard deviceCount <= DeviceReadCursorLimits.maxDevices else {
      throw DeviceReadCursorError.corruptState
    }
    var cursors: [UUID: [String: DeviceReadCursor]] = [:]
    var previousDevice: Data?
    for _ in 0..<deviceCount {
      let deviceID = try reader.uuid()
      let deviceBytes = encoded(deviceID)
      if let previousDevice {
        guard previousDevice.lexicographicallyPrecedes(deviceBytes) else {
          throw DeviceReadCursorError.corruptState
        }
      }
      previousDevice = deviceBytes

      let threadCount = Int(try reader.uint16())
      guard threadCount <= DeviceReadCursorLimits.maxThreadsPerDevice else {
        throw DeviceReadCursorError.corruptState
      }
      var threads: [String: DeviceReadCursor] = [:]
      var previousThread: Data?
      for _ in 0..<threadCount {
        let threadBytes = try reader.variable()
        if let previousThread {
          guard previousThread.lexicographicallyPrecedes(threadBytes) else {
            throw DeviceReadCursorError.corruptState
          }
        }
        previousThread = threadBytes
        guard let threadID = String(bytes: threadBytes, encoding: .utf8) else {
          throw DeviceReadCursorError.corruptState
        }
        threads[threadID] = try DeviceReadCursor(
          deviceID: deviceID,
          threadID: threadID,
          readSequence: try reader.uint64(),
          updatedAtEpochSeconds: try reader.uint64()
        )
      }
      cursors[deviceID] = threads
    }
    try reader.requireEnd()
    return DeviceReadCursorState(writeSequence: writeSequence, cursors: cursors)
  }

  // MARK: - Primitives

  private static func append(byte: UInt8, to blob: inout Data) throws {
    try append(bytes: Data([byte]), to: &blob)
  }

  private static func append(count: Int, to blob: inout Data) throws {
    guard count <= Int(UInt16.max) else { throw DeviceReadCursorError.cursorLimitExceeded }
    try append(bytes: Data(withUnsafeBytes(of: UInt16(count).bigEndian) { Array($0) }), to: &blob)
  }

  private static func append(uint64: UInt64, to blob: inout Data) throws {
    try append(bytes: Data(withUnsafeBytes(of: uint64.bigEndian) { Array($0) }), to: &blob)
  }

  private static func append(variable: Data, to blob: inout Data) throws {
    guard variable.count <= Int(UInt16.max) else {
      throw DeviceReadCursorError.cursorLimitExceeded
    }
    try append(count: variable.count, to: &blob)
    try append(bytes: variable, to: &blob)
  }

  private static func append(bytes: Data, to blob: inout Data) throws {
    guard bytes.count <= DeviceReadCursorLimits.maximumBlobByteCount - blob.count else {
      throw DeviceReadCursorError.cursorLimitExceeded
    }
    blob.append(bytes)
  }

  private static func encoded(_ id: UUID) -> Data {
    withUnsafeBytes(of: id.uuid) { Data($0) }
  }

  private struct Reader {
    private let bytes: Data
    private var offset = 0

    init(_ blob: Data) { bytes = Data(blob) }

    mutating func byte() throws -> UInt8 { try take(1)[0] }

    mutating func uint16() throws -> UInt16 {
      try take(2).reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
    }

    mutating func uint64() throws -> UInt64 {
      try take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    mutating func uuid() throws -> UUID {
      let raw = Array(try take(16))
      return UUID(
        uuid: (
          raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
          raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
        ))
    }

    mutating func variable() throws -> Data {
      try take(Int(try uint16()))
    }

    func requireEnd() throws {
      guard offset == bytes.count else { throw DeviceReadCursorError.corruptState }
    }

    private mutating func take(_ count: Int) throws -> Data {
      guard count >= 0, bytes.count - offset >= count else {
        throw DeviceReadCursorError.corruptState
      }
      defer { offset += count }
      return bytes.subdata(in: offset..<(offset + count))
    }
  }
}

/// Production read-cursor storage: one file under Application Support.
///
/// Read cursors hold no key material and no authority, so they live in the
/// filesystem rather than the Keychain — but they are still device-local UI
/// state, so the directory is `0700`, the file is `0600`, writes are atomic,
/// and the file is excluded from backup so it never leaves the machine.
public struct FileBackedReadCursorStorage: DeviceReadCursorStorage {
  private let fileURL: URL

  /// Resolves the production location, creating the container directory with
  /// owner-only permissions when it does not exist.
  public init(fileURL: URL? = nil) throws {
    if let fileURL {
      self.fileURL = fileURL
    } else {
      let support = try FileManager.default.url(
        for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
      self.fileURL =
        support
        .appendingPathComponent("CodexMicro", isDirectory: true)
        .appendingPathComponent("device-read-cursors.blob")
    }
    try Self.prepareContainer(for: self.fileURL)
  }

  public func load() throws -> Data? {
    guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
    guard let data = try? Data(contentsOf: fileURL) else {
      throw DeviceReadCursorError.storageUnavailable
    }
    guard data.count <= DeviceReadCursorLimits.maximumBlobByteCount else {
      throw DeviceReadCursorError.corruptState
    }
    return data
  }

  public func replace(blob: Data) throws {
    guard blob.count <= DeviceReadCursorLimits.maximumBlobByteCount else {
      throw DeviceReadCursorError.cursorLimitExceeded
    }
    do {
      try blob.write(to: fileURL, options: [.atomic, .completeFileProtection])
      try FileManager.default.setAttributes(
        [.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
      var resource = URLResourceValues()
      resource.isExcludedFromBackup = true
      var target = fileURL
      try target.setResourceValues(resource)
    } catch {
      throw DeviceReadCursorError.storageUnavailable
    }
  }

  private static func prepareContainer(for fileURL: URL) throws {
    let directory = fileURL.deletingLastPathComponent()
    do {
      try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    } catch {
      throw DeviceReadCursorError.storageUnavailable
    }
  }
}
