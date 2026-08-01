import Foundation
import OSLog

public enum SpikeLogCode: String, CaseIterable, Sendable {
  case bonjourPublishFailed = "bonjour_publish_failed"
  case certificateBlocked = "certificate_blocked"
  case connectionAccepted = "connection_accepted"
  case connectionClosed = "connection_closed"
  case connectionLimitReached = "connection_limit_reached"
  case identityCleanupFailed = "identity_cleanup_failed"
  case identityMissing = "identity_missing"
  case identityMismatch = "identity_mismatch"
  case interfaceDenied = "interface_denied"
  case interfaceEligible = "interface_eligible"
  case keychainUnavailable = "keychain_unavailable"
  case listenerReady = "listener_ready"
  case listenerStartFailed = "listener_start_failed"
  case listenerStopped = "listener_stopped"
  case pinMismatch = "pin_mismatch"
  case policyRejected = "policy_rejected"
  case probeCompleted = "probe_completed"
  case probeFailed = "probe_failed"
}

public struct ClosedLogEvent: Equatable, Sendable {
  public let code: SpikeLogCode
  public let count: Int

  public init(code: SpikeLogCode, count: Int) {
    self.code = code
    self.count = count
  }
}

public protocol ClosedCodeLogging: Sendable {
  func record(_ code: SpikeLogCode, count: Int)
}

extension ClosedCodeLogging {
  public func record(_ code: SpikeLogCode) {
    record(code, count: 1)
  }
}

public struct ConsoleClosedCodeLogger: ClosedCodeLogging {
  public init() {}

  public func record(_ code: SpikeLogCode, count: Int) {
    guard count >= 0 else { return }
    print("code=\(code.rawValue) count=\(count)")
  }
}

public struct OSClosedCodeLogger: ClosedCodeLogging {
  private let logger = Logger(
    subsystem: "com.codexmicro.phase2transport.spike", category: "transport")

  public init() {}

  public func record(_ code: SpikeLogCode, count: Int) {
    guard count >= 0 else { return }
    logger.notice("code=\(code.rawValue, privacy: .public) count=\(count, privacy: .public)")
  }
}

public final class InMemoryClosedCodeLogger: ClosedCodeLogging, @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [ClosedLogEvent] = []

  public init() {}

  public func record(_ code: SpikeLogCode, count: Int) {
    guard count >= 0 else { return }
    lock.withLock {
      storage.append(ClosedLogEvent(code: code, count: count))
    }
  }

  public var events: [ClosedLogEvent] {
    lock.withLock { storage }
  }
}
