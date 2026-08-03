import Foundation
import os

/// The complete closed vocabulary the listener may log (plan §2 invariant
/// 19, ADR §13).
///
/// Adding a case is the review point. No API on this path accepts a string,
/// so no endpoint, address, header, certificate, fingerprint, frame byte,
/// device ID, or payload can reach a log line: the only variable a caller
/// supplies alongside a code is a nonnegative count.
public enum ListenerLogCode: String, CaseIterable, Sendable {
  /// The listener bound and is accepting connections.
  case listenerReady = "listener_ready"
  /// Startup failed before the listener was reachable.
  case listenerStartFailed = "listener_start_failed"
  /// The listener reached its terminal phase.
  case listenerStopped = "listener_stopped"
  /// Teardown could not complete every step.
  case listenerCleanupFailed = "listener_cleanup_failed"
  /// A startup prerequisite was unavailable, so LAN stays disabled.
  case prerequisiteUnavailable = "prerequisite_unavailable"
  /// The configured bind target was ineligible.
  case interfaceDenied = "interface_denied"
  /// A live interface object could not be pinned.
  case interfaceUnavailable = "interface_unavailable"
  /// A connection was accepted.
  case connectionAccepted = "connection_accepted"
  /// A connection was refused by an admission ceiling.
  case connectionRefused = "connection_refused"
  /// A connection closed.
  case connectionClosed = "connection_closed"
  /// The HTTP upgrade was rejected by policy.
  case upgradeRejected = "upgrade_rejected"
  /// The TLS + upgrade deadline elapsed.
  case upgradeDeadlineElapsed = "upgrade_deadline_elapsed"
  /// The authentication deadline elapsed.
  case authenticationDeadlineElapsed = "authentication_deadline_elapsed"
  /// A frame violated the ADR §9 frame policy.
  case frameRejected = "frame_rejected"
  /// A message arrived that the pre-authentication allowlist forbids.
  case preAuthMessageRejected = "preauth_message_rejected"
  /// The inbound message or byte rate ceiling was exceeded.
  case inboundRateExceeded = "inbound_rate_exceeded"
  /// The outbound queue bound was exceeded.
  case outboundQueueExceeded = "outbound_queue_exceeded"
  /// The connection stayed non-writable past the ceiling.
  case slowConsumerClosed = "slow_consumer_closed"
  /// No matching pong arrived inside the deadline.
  case pongDeadlineElapsed = "pong_deadline_elapsed"
  /// The post-upgrade application idle expiry elapsed.
  case idleExpired = "idle_expired"
  /// A connection completed authentication.
  case connectionAuthenticated = "connection_authenticated"
  /// A post-authentication application message was refused.
  case applicationMessageRejected = "application_message_rejected"
  /// One already-authorized observation batch was sealed and written.
  case observationDelivered = "observation_delivered"
  /// One closed command result was sealed and written.
  case commandResultDelivered = "command_result_delivered"
  /// A handshake message was refused by its per-source ceiling.
  case handshakeRateExceeded = "handshake_rate_exceeded"
  /// A peer exceeded the pre-upgrade byte budget.
  case preUpgradeBudgetExceeded = "preupgrade_budget_exceeded"
}

/// One recorded listener log event: a closed code and a nonnegative count.
public struct ListenerLogEvent: Equatable, Sendable {
  /// The closed code.
  public let code: ListenerLogCode
  /// A nonnegative count. Never an identifier, size of peer data, or index
  /// into peer-controlled state.
  public let count: Int

  /// Creates an event.
  public init(code: ListenerLogCode, count: Int) {
    self.code = code
    self.count = count
  }
}

/// The listener's only logging API. It accepts a closed code and a
/// nonnegative count and nothing else.
public protocol ListenerLogging: Sendable {
  /// Records one event. Negative counts are dropped by every conforming
  /// implementation.
  func record(_ code: ListenerLogCode, count: Int)
}

extension ListenerLogging {
  /// Records one occurrence of `code`.
  public func record(_ code: ListenerLogCode) {
    record(code, count: 1)
  }
}

/// Production sink writing to unified logging. Both interpolations are
/// compile-time-safe values, so the public privacy level is correct.
public struct OSListenerLogger: ListenerLogging {
  private let logger: Logger

  /// Creates a logger.
  public init(
    subsystem: String = "com.codexmicro.bridge",
    category: String = "listener"
  ) {
    logger = Logger(subsystem: subsystem, category: category)
  }

  public func record(_ code: ListenerLogCode, count: Int) {
    guard count >= 0 else { return }
    logger.notice("\(code.rawValue, privacy: .public) count=\(count, privacy: .public)")
  }
}

/// Discards everything. The default for tests that assert behaviour rather
/// than logging.
public struct DiscardingListenerLogger: ListenerLogging {
  /// Creates the sink.
  public init() {}

  public func record(_ code: ListenerLogCode, count: Int) {}
}

/// Deterministic recorder used by sentinel tests to assert that only closed
/// codes and counts ever reach a sink.
public final class InMemoryListenerLogger: ListenerLogging, @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [ListenerLogEvent] = []

  /// Creates an empty recorder.
  public init() {}

  public func record(_ code: ListenerLogCode, count: Int) {
    guard count >= 0 else { return }
    lock.withLock { storage.append(ListenerLogEvent(code: code, count: count)) }
  }

  /// Every recorded event, in order.
  public var events: [ListenerLogEvent] {
    lock.withLock { storage }
  }

  /// The number of recorded events carrying `code`.
  public func count(of code: ListenerLogCode) -> Int {
    lock.withLock { storage.filter { $0.code == code }.count }
  }
}
