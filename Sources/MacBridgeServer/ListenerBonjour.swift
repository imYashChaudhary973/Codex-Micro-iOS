import Foundation
import Network

/// The exact, static Bonjour record this bridge may publish (ADR §12).
///
/// **Everything here is a compile-time constant.** There is no host name, no
/// device or user name, no identifier, no fingerprint, no interface data, no
/// project data, and no secret — not filtered out, but absent: the type
/// exposes no way to supply one. Two Macs on the same LAN publish
/// byte-identical records, which is the point: the advertisement says a
/// Codex Micro bridge exists here and nothing else. Pairing carries the
/// identity, through the QR payload and the signed transcript.
public enum ListenerBonjourRecord {
  /// The static service-instance name. Deliberately not the host name.
  public static let instanceName = "Codex Micro"
  /// The registered service type.
  public static let serviceType = "_codexmicro._tcp"
  /// The local mDNS domain. Nothing is ever published outside it.
  public static let domain = "local."
  /// The exact TXT keys this bridge may publish.
  ///
  /// Only the wire-protocol major version, so a device can skip a bridge it
  /// cannot speak to before opening a connection. It is the same constant on
  /// every installation.
  public static let txtRecord: [String: String] = ["v": "1"]

  /// The `NWListener.Service` for the record. Built from constants only.
  public static func service() -> NWListener.Service {
    NWListener.Service(
      name: instanceName,
      type: serviceType,
      domain: domain,
      txtRecord: NWTXTRecord(txtRecord)
    )
  }

  /// Whether a candidate TXT dictionary is exactly the allowlist.
  ///
  /// Used by the publisher and asserted by test, so an added key fails rather
  /// than silently advertising a new field.
  public static func isAllowlisted(txtRecord candidate: [String: String]) -> Bool {
    candidate == txtRecord
  }
}

/// Closed Bonjour failure vocabulary.
public enum ListenerBonjourFailure: Error, Equatable, Sendable {
  /// Publication did not reach the ready state.
  case publicationFailed
  /// Removal did not complete, so the record may still be visible.
  case removalFailed
  /// The record offered for publication is not the exact allowlist.
  case recordNotAllowlisted
}

/// Publishes and removes the bridge's Bonjour advertisement.
///
/// A seam because publication is the one listener behaviour that cannot be
/// proven deterministically: `NWListener.service` is public API but NIOTS
/// warns that arbitrary underlying-listener modification is unsupported
/// (ADR §16), so the production implementation needs physical re-verification
/// while a deterministic double drives the lifecycle rules.
public protocol ListenerBonjourPublishing: Sendable {
  /// Publishes the static record. Throws when publication does not reach
  /// ready; the caller then rolls the listener back.
  func publish() async throws

  /// Removes the record. Throws when removal cannot be confirmed.
  func remove() async throws
}

/// The fail-closed default: this build advertises nothing.
///
/// A listener with no wired publisher runs without discovery rather than
/// advertising something unverified. Direct-endpoint pairing through the QR
/// payload does not need Bonjour.
public struct DisabledListenerBonjourPublisher: ListenerBonjourPublishing {
  public init() {}

  public func publish() async throws {}

  public func remove() async throws {}
}

/// Drives the ADR §12 advertisement lifecycle around a listener.
///
/// Three rules, and the order in each is the whole point:
///
/// 1. **Advertise only after readiness.** The listener must be bound and
///    accepting first, so a device that discovers the service can always
///    reach it. Nothing advertises during startup.
/// 2. **A publication failure rolls the listener back.** The bridge is either
///    reachable and advertised, or neither. It never runs advertised-but-
///    broken, and never runs reachable-but-silently-unadvertised after the
///    user asked for discovery.
/// 3. **Disable removes the advertisement before closing the listener.** The
///    other order leaves a record pointing at a closed port for as long as
///    mDNS caches it.
///
/// The coordinator owns only that ordering; it binds no socket and publishes
/// no record itself.
public actor ListenerBonjourCoordinator {
  private let publisher: any ListenerBonjourPublishing
  private let logger: any ListenerLogging
  private var published = false

  public init(
    publisher: any ListenerBonjourPublishing = DisabledListenerBonjourPublisher(),
    logger: any ListenerLogging = DiscardingListenerLogger()
  ) {
    self.publisher = publisher
    self.logger = logger
  }

  /// Whether a record is currently advertised.
  public var isPublished: Bool { published }

  /// Publishes after the listener reached readiness, rolling the listener
  /// back when publication fails.
  ///
  /// `rollback` is invoked **before** the error is rethrown, so no caller can
  /// observe a failed publication while the listener is still bound.
  public func publishAfterReadiness(
    rollback: () async -> Void
  ) async throws {
    guard !published else { return }
    do {
      try await publisher.publish()
    } catch {
      logger.record(.bonjourPublishFailed)
      await rollback()
      throw ListenerBonjourFailure.publicationFailed
    }
    published = true
    logger.record(.bonjourPublished)
  }

  /// Removes the advertisement, then runs `closeListener`.
  ///
  /// Removal runs first even when it fails: a record that may still be
  /// visible is a reason to report a failure, never a reason to leave the
  /// listener running.
  public func removeThenClose(closeListener: () async -> Void) async throws {
    guard published else {
      await closeListener()
      return
    }
    var removalFailed = false
    do {
      try await publisher.remove()
    } catch {
      removalFailed = true
      logger.record(.bonjourRemoveFailed)
    }
    published = false
    if !removalFailed {
      logger.record(.bonjourRemoved)
    }
    await closeListener()
    if removalFailed {
      throw ListenerBonjourFailure.removalFailed
    }
  }
}
