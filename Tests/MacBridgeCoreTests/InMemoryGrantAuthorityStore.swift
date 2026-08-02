import Foundation

@testable import MacBridgeCore

/// Deterministic in-memory grant-authority storage with injectable
/// failures for missing, duplicate, corrupt, store-error, and rollback
/// simulation.
final class InMemoryGrantAuthorityStore: GrantAuthorityStorage, @unchecked Sendable {
  private let lock = NSLock()
  private var blob: Data? = Data()
  private var loadFailure: DeviceGrantAuthorityError?
  private var replaceFailure: DeviceGrantAuthorityError?
  private var log: [Data] = []

  func load() throws -> GrantAuthorityLoadResult {
    lock.lock()
    defer { lock.unlock() }
    if let loadFailure {
      throw loadFailure
    }
    guard let blob else {
      throw DeviceGrantAuthorityError.authorityMissing
    }
    return blob.isEmpty ? .empty : .blob(blob)
  }

  func replace(blob: Data) throws {
    lock.lock()
    defer { lock.unlock() }
    if let replaceFailure {
      throw replaceFailure
    }
    self.blob = blob
    log.append(blob)
  }

  // MARK: - Test hooks

  /// Every blob accepted by `replace`, in write order.
  var writeLog: [Data] {
    lock.lock()
    defer { lock.unlock() }
    return log
  }

  /// The currently persisted blob, or `nil` when empty.
  var currentBlob: Data? {
    lock.lock()
    defer { lock.unlock() }
    return blob
  }

  /// Overwrites the persisted blob directly (corruption/rollback setup).
  func setBlob(_ blob: Data?) {
    lock.lock()
    defer { lock.unlock() }
    self.blob = blob
  }

  /// Removes the item so loading fails with `authorityMissing`.
  func clear() {
    lock.lock()
    defer { lock.unlock() }
    blob = nil
  }

  /// Makes every `load` throw `failure` until cleared with `nil`.
  func failLoads(with failure: DeviceGrantAuthorityError?) {
    lock.lock()
    defer { lock.unlock() }
    loadFailure = failure
  }

  /// Makes every `replace` throw `failure` until cleared with `nil`.
  func failReplacements(with failure: DeviceGrantAuthorityError?) {
    lock.lock()
    defer { lock.unlock() }
    replaceFailure = failure
  }
}

/// Deterministic injectable epoch-seconds clock.
final class TestGrantClock: @unchecked Sendable {
  private let lock = NSLock()
  private var epochSeconds: UInt64

  init(epochSeconds: UInt64) {
    self.epochSeconds = epochSeconds
  }

  var now: UInt64 {
    lock.lock()
    defer { lock.unlock() }
    return epochSeconds
  }

  func advance(to epochSeconds: UInt64) {
    lock.lock()
    defer { lock.unlock() }
    self.epochSeconds = epochSeconds
  }

  var reader: @Sendable () -> UInt64 {
    { self.now }
  }
}
