import CompanionProtocol
import Foundation

/// Closed read-cursor failure vocabulary. Carries no content.
public enum DeviceReadCursorError: Error, Equatable, Sendable {
  /// The thread is outside the device's current project scope, has no
  /// attribution, or the device may not observe at all.
  case notAuthorized
  /// The proposed position is not strictly ahead of the stored one. Read
  /// cursors only ever move forward (plan §9 P0 mutation allowlist).
  case notMonotonic
  /// The position or a stored counter reached its fixed width.
  case counterOverflow
  /// The device already tracks the maximum number of threads, or the encoded
  /// state would exceed its bound.
  case cursorLimitExceeded
  /// The persisted blob is malformed, truncated, oversized, carries an
  /// unknown version or domain, has trailing bytes, or contains duplicate or
  /// non-canonically ordered entries.
  case corruptState
  /// Reading or writing the store failed. There is no memory-only fallback.
  case storageUnavailable
}

/// Bounds for persisted read-cursor state.
public enum DeviceReadCursorLimits {
  /// Maximum encoded blob size in bytes (64 KiB), matching the authority's
  /// own bound.
  public static let maximumBlobByteCount = 64 * 1024
  /// Maximum threads one device may track a read position for.
  public static let maxThreadsPerDevice = 512
  /// Maximum devices tracked at once.
  public static let maxDevices = 64
}

/// One device's read position in one thread.
///
/// This is **device-local UI state**, not authority: it decides nothing about
/// what a device may see. It is stored on the Mac only so a device that
/// reinstalls or reconnects does not lose its unread marks, and it is
/// disclosed and mutated exclusively inside that device's current project
/// scope.
public struct DeviceReadCursor: Equatable, Sendable {
  public let deviceID: UUID
  public let threadID: String
  /// Monotonic per-thread read position, in the device's own authorized-view
  /// sequence namespace.
  public let readSequence: UInt64
  /// Display-neutral last-update instant in epoch seconds.
  public let updatedAtEpochSeconds: UInt64

  public init(
    deviceID: UUID,
    threadID: String,
    readSequence: UInt64,
    updatedAtEpochSeconds: UInt64
  ) throws {
    guard !threadID.isEmpty,
      threadID.utf8.count <= SecureObservationLimits.maxThreadIDBytes,
      !threadID.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
      readSequence >= 1,
      readSequence < UInt64.max
    else {
      throw DeviceReadCursorError.corruptState
    }
    self.deviceID = deviceID
    self.threadID = threadID
    self.readSequence = readSequence
    self.updatedAtEpochSeconds = updatedAtEpochSeconds
  }
}

/// The complete persisted read-cursor state.
struct DeviceReadCursorState: Equatable, Sendable {
  /// Monotonic anti-rollback write sequence. `0` only for the never-persisted
  /// fresh-install state.
  let writeSequence: UInt64
  /// Cursors keyed by device, then thread.
  let cursors: [UUID: [String: DeviceReadCursor]]

  static let freshInstall = DeviceReadCursorState(writeSequence: 0, cursors: [:])
}

/// Byte-level persistence seam for read-cursor state.
///
/// The blob is loaded and replaced whole, exactly like the grant authority's,
/// so state can never be observed partially written. Implementations must be
/// thread-safe and throw only ``DeviceReadCursorError`` cases.
public protocol DeviceReadCursorStorage: Sendable {
  /// Loads the persisted blob, or `nil` when nothing has ever been written.
  ///
  /// Unlike the grant authority, absence is a valid fresh state here: read
  /// cursors carry no authority, so a missing file loses UI state rather than
  /// creating a security condition.
  func load() throws -> Data?

  /// Atomically replaces the persisted value.
  func replace(blob: Data) throws
}

/// Deterministic in-memory read-cursor storage.
public final class InMemoryReadCursorStorage: DeviceReadCursorStorage, @unchecked Sendable {
  private let lock = NSLock()
  private var blob: Data?

  public init() {}

  public func load() throws -> Data? {
    lock.lock()
    defer { lock.unlock() }
    return blob
  }

  public func replace(blob: Data) throws {
    lock.lock()
    defer { lock.unlock() }
    self.blob = blob
  }
}

/// The Mac-side owner of every device's read positions.
///
/// Three rules define it, and all three are enforced here rather than by any
/// caller:
///
/// - **Device-own.** Every operation takes the authenticated device ID and
///   touches only that device's entries. There is no cross-device read.
/// - **Scoped.** A position is disclosed or advanced only for a thread inside
///   the device's *current* Mac-stored project scope, which is re-read for
///   every call. A thread with no attribution is never in scope.
/// - **Monotonic.** A position only ever moves strictly forward. A regressing
///   or repeated value is rejected rather than silently ignored, so a replayed
///   command cannot quietly unread a thread.
///
/// Writes persist before they become visible, and a persist failure leaves the
/// prior state in force.
public actor DeviceReadCursorStore {
  private let storage: any DeviceReadCursorStorage
  private let scopes: any ObservationScopeProviding
  private let attribution: any ThreadProjectAttributing
  private let clock: @Sendable () -> UInt64
  private var state: DeviceReadCursorState

  public init(
    storage: any DeviceReadCursorStorage,
    scopes: any ObservationScopeProviding,
    attribution: any ThreadProjectAttributing,
    clock: @escaping @Sendable () -> UInt64 = {
      UInt64(max(0, Date().timeIntervalSince1970.rounded(.down)))
    }
  ) throws {
    self.storage = storage
    self.scopes = scopes
    self.attribution = attribution
    self.clock = clock
    guard let blob = try Self.loadBlob(from: storage) else {
      self.state = .freshInstall
      return
    }
    self.state = try DeviceReadCursorBlobCodec.decode(blob)
  }

  /// The device's read positions, restricted to threads currently in scope.
  ///
  /// A position for a thread that has since left the device's scope is
  /// retained but never disclosed, so a later scope restoration does not lose
  /// the mark while a reduction does not leak that the thread exists.
  public func cursors(deviceID: UUID) async throws -> [DeviceReadCursor] {
    let scope = try await requireScope(deviceID: deviceID)
    return (state.cursors[deviceID] ?? [:]).values
      .filter { scope.permits(projectID: attribution.projectID(forThreadID: $0.threadID)) }
      .sorted { $0.threadID < $1.threadID }
  }

  /// The device's read position in one in-scope thread.
  public func cursor(deviceID: UUID, threadID: String) async throws -> DeviceReadCursor? {
    let scope = try await requireScope(deviceID: deviceID)
    try requireInScope(threadID: threadID, scope: scope)
    return state.cursors[deviceID]?[threadID]
  }

  /// Advances the device's read position in one in-scope thread.
  ///
  /// This is the storage-model half of the Step 2.9 `markThreadRead` command:
  /// it performs no Codex call and produces no network message.
  @discardableResult
  public func advance(
    deviceID: UUID,
    threadID: String,
    to readSequence: UInt64
  ) async throws -> DeviceReadCursor {
    let scope = try await requireScope(deviceID: deviceID)
    try requireInScope(threadID: threadID, scope: scope)
    guard readSequence >= 1, readSequence < UInt64.max else {
      throw DeviceReadCursorError.counterOverflow
    }

    var deviceCursors = state.cursors[deviceID] ?? [:]
    if let existing = deviceCursors[threadID] {
      guard readSequence > existing.readSequence else {
        throw DeviceReadCursorError.notMonotonic
      }
    } else {
      guard deviceCursors.count < DeviceReadCursorLimits.maxThreadsPerDevice else {
        throw DeviceReadCursorError.cursorLimitExceeded
      }
      guard
        state.cursors[deviceID] != nil
          || state.cursors.count < DeviceReadCursorLimits.maxDevices
      else {
        throw DeviceReadCursorError.cursorLimitExceeded
      }
    }

    let cursor = try DeviceReadCursor(
      deviceID: deviceID,
      threadID: threadID,
      readSequence: readSequence,
      updatedAtEpochSeconds: clock()
    )
    deviceCursors[threadID] = cursor
    var cursors = state.cursors
    cursors[deviceID] = deviceCursors
    try commit(cursors)
    return cursor
  }

  /// Discards every position a device holds.
  ///
  /// Called after an authorization commit that ends the device's access, so
  /// no read state outlives the grant that authorized it.
  public func purge(deviceID: UUID) throws {
    guard state.cursors[deviceID] != nil else { return }
    var cursors = state.cursors
    cursors.removeValue(forKey: deviceID)
    try commit(cursors)
  }

  /// Discards positions for threads that left the device's current scope.
  ///
  /// Unlike ``purge(deviceID:)`` this is used after a *reduction*: the device
  /// keeps access, so only the now-unauthorized entries are dropped.
  @discardableResult
  public func purgeOutOfScope(deviceID: UUID) async throws -> Int {
    let scope = try await requireScope(deviceID: deviceID)
    guard let deviceCursors = state.cursors[deviceID] else { return 0 }
    let retained = deviceCursors.filter {
      scope.permits(projectID: attribution.projectID(forThreadID: $0.key))
    }
    guard retained.count != deviceCursors.count else { return 0 }
    var cursors = state.cursors
    cursors[deviceID] = retained
    try commit(cursors)
    return deviceCursors.count - retained.count
  }

  /// The monotonic write sequence, for anti-rollback assertions in tests.
  public func writeSequence() -> UInt64 {
    state.writeSequence
  }

  // MARK: - Persist before visible

  private func commit(_ cursors: [UUID: [String: DeviceReadCursor]]) throws {
    guard state.writeSequence < UInt64.max else {
      throw DeviceReadCursorError.counterOverflow
    }
    let next = DeviceReadCursorState(
      writeSequence: state.writeSequence + 1,
      cursors: cursors
    )
    let blob = try DeviceReadCursorBlobCodec.encode(next)
    do {
      try storage.replace(blob: blob)
    } catch let error as DeviceReadCursorError {
      throw error
    } catch {
      throw DeviceReadCursorError.storageUnavailable
    }
    state = next
  }

  private func requireScope(deviceID: UUID) async throws -> AuthorizedViewScope {
    let result: ObservationScopeResult
    do {
      result = try await scopes.observationScope(deviceID: deviceID)
    } catch {
      throw DeviceReadCursorError.storageUnavailable
    }
    switch result {
    case .scoped(let scope): return scope
    case .notObservable: throw DeviceReadCursorError.notAuthorized
    }
  }

  private func requireInScope(threadID: String, scope: AuthorizedViewScope) throws {
    guard scope.permits(projectID: attribution.projectID(forThreadID: threadID)) else {
      throw DeviceReadCursorError.notAuthorized
    }
  }

  private static func loadBlob(from storage: any DeviceReadCursorStorage) throws -> Data? {
    do {
      return try storage.load()
    } catch let error as DeviceReadCursorError {
      throw error
    } catch {
      throw DeviceReadCursorError.storageUnavailable
    }
  }
}
