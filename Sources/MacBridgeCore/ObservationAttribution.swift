import CompanionProtocol
import Foundation
import Security

/// Closed observation-projection failure vocabulary. Carries no content
/// (plan §2 invariant 19).
public enum ObservationProjectionError: Error, Equatable, Sendable {
  /// The device's authorized-view sequence reached its fixed width. The
  /// view is disabled rather than wrapping (plan §9 counter widths); the
  /// bridge rotates the journal epoch and forces fresh snapshots.
  case sequenceExhausted
  /// The projected value violates a declared wire bound — more threads than
  /// one snapshot may carry, or an identifier outside its length bound.
  case projectionOversized
  /// Randomness was unavailable, so no journal epoch could be minted.
  case entropyUnavailable
}

/// Seam minting the 128-bit journal epoch (plan §9 counter widths).
///
/// The epoch is drawn fresh on every bridge-process start, which is what
/// makes a cursor from a previous process foreign rather than replayable: a
/// restarted bridge holds different in-memory journal contents at the same
/// sequence numbers, so sequence alone must never be trusted across
/// processes.
public protocol JournalEpochMinting: Sendable {
  func mintJournalEpoch() throws -> JournalEpoch
}

/// Production epoch source backed by the system CSPRNG.
public struct SystemJournalEpochMint: JournalEpochMinting {
  public init() {}

  public func mintJournalEpoch() throws -> JournalEpoch {
    var bytes = [UInt8](repeating: 0, count: SecureTransportLimits.journalEpochByteCount)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
      throw ObservationProjectionError.entropyUnavailable
    }
    guard let epoch = try? JournalEpoch(rawBytes: Data(bytes)) else {
      throw ObservationProjectionError.entropyUnavailable
    }
    return epoch
  }
}

/// Resolves an opaque thread identifier to the opaque project identifier
/// that authorization is decided against.
///
/// **Fail closed by contract.** Returning `nil` means the thread cannot be
/// attributed, and an unattributable thread is visible to **no** device —
/// not to a device with an empty allowlist, and not to a device allowed
/// every project it knows about. Project scope is the only thing standing
/// between two devices paired to the same Mac (plan §2 invariant 5), so a
/// thread whose project is unknown is never disclosed on the guess that it
/// might be permitted.
///
/// The Phase 1 app-server surface this bridge consumes carries no project or
/// workspace attribution, so no production resolver exists yet; the Mac
/// assembly supplies one when it selects projects for a grant (Step 2.13).
/// Until then ``DeniedThreadProjectAttribution`` is the default and the
/// observation surface discloses nothing.
public protocol ThreadProjectAttributing: Sendable {
  func projectID(forThreadID threadID: String) -> String?
}

/// The default attribution: nothing is attributable, so nothing is visible.
public struct DeniedThreadProjectAttribution: ThreadProjectAttributing {
  public init() {}

  public func projectID(forThreadID threadID: String) -> String? { nil }
}

/// Explicit table-backed attribution the Mac assembly populates.
///
/// Entries are validated on insertion against the same opaque-project bound
/// the grant authority enforces, so an over-long or control-character
/// project ID can never enter the table and later widen a device's view.
public final class ThreadProjectTable: ThreadProjectAttributing, @unchecked Sendable {
  private let lock = NSLock()
  private var attribution: [String: String]

  public init(attribution: [String: String] = [:]) {
    self.attribution = attribution.filter { Self.isWellFormed(thread: $0.key, project: $0.value) }
  }

  public func projectID(forThreadID threadID: String) -> String? {
    lock.lock()
    defer { lock.unlock() }
    return attribution[threadID]
  }

  /// Attributes a thread, replacing any previous attribution. A malformed
  /// pair is rejected and leaves the table unchanged.
  @discardableResult
  public func attribute(threadID: String, projectID: String) -> Bool {
    guard Self.isWellFormed(thread: threadID, project: projectID) else { return false }
    lock.lock()
    defer { lock.unlock() }
    attribution[threadID] = projectID
    return true
  }

  /// Removes a thread's attribution, making it invisible again.
  public func forget(threadID: String) {
    lock.lock()
    defer { lock.unlock() }
    attribution.removeValue(forKey: threadID)
  }

  private static func isWellFormed(thread: String, project: String) -> Bool {
    isBounded(thread, limit: SecureObservationLimits.maxThreadIDBytes)
      && isBounded(project, limit: SecureObservationLimits.maxProjectIDBytes)
  }

  private static func isBounded(_ value: String, limit: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= limit
      && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }
}
