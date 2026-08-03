import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import NIOCore
import NIOHTTP1
import Network
import Security
import X509

@testable import MacBridgeServer

/// Controllable monotonic clock. Every ceiling in the listener reads its
/// time through this seam in tests, so no test sleeps.
final class ManualListenerClock: @unchecked Sendable {
  private let lock = NSLock()
  private var nanoseconds: UInt64

  init(nanoseconds: UInt64 = 1_000_000_000) {
    self.nanoseconds = nanoseconds
  }

  var now: @Sendable () -> UInt64 {
    { [self] in lock.withLock { nanoseconds } }
  }

  func advance(seconds: Double) {
    lock.withLock { nanoseconds += UInt64(seconds * 1_000_000_000) }
  }

  func advance(milliseconds: UInt64) {
    lock.withLock { nanoseconds += milliseconds * 1_000_000 }
  }
}

/// Ephemeral, non-persistent TLS serving identity.
///
/// A Secure Enclave key needs an entitled signed host, which `swift test`
/// does not have, so the loopback tests serve a process-local key that never
/// touches the Keychain. Production startup uses
/// `ListenerServingIdentity.init(certificate:identity:)`, whose assembly
/// refuses anything that is not Secure Enclave-backed.
struct StubPrerequisiteFailure: Error {}

final class ScriptedHandshakeHandler: ListenerHandshakeHandling, @unchecked Sendable {
  private let lock = NSLock()
  private var outcomes: [ListenerHandshakeOutcome]
  private let repeating: ListenerHandshakeOutcome?
  private var received: [ListenerHandshakeKind] = []
  private var abandoned: [UUID] = []

  init(
    outcomes: [ListenerHandshakeOutcome] = [],
    repeating: ListenerHandshakeOutcome? = nil
  ) {
    self.outcomes = outcomes
    self.repeating = repeating
  }

  var receivedKinds: [ListenerHandshakeKind] {
    lock.withLock { received }
  }

  var abandonedConnections: [UUID] {
    lock.withLock { abandoned }
  }

  func handle(
    _ envelope: ListenerHandshakeEnvelope,
    connectionID: UUID
  ) async -> ListenerHandshakeOutcome {
    lock.withLock {
      received.append(envelope.kind)
      if !outcomes.isEmpty { return outcomes.removeFirst() }
      return repeating ?? .close(.authenticationFailed)
    }
  }

  func abandon(connectionID: UUID) async {
    lock.withLock { abandoned.append(connectionID) }
  }
}

enum UpgradeRequestFixture {
  static let validKey = Data(repeating: 0x2A, count: 16).base64EncodedString()

  static func head(
    method: HTTPMethod = .GET,
    version: HTTPVersion = .http1_1,
    uri: String = ListenerUpgradePolicy.path,
    mutate: (inout HTTPHeaders) -> Void = { _ in }
  ) -> HTTPRequestHead {
    var headers = HTTPHeaders()
    headers.add(name: "Host", value: "10.0.0.1:8443")
    headers.add(name: "Upgrade", value: "websocket")
    headers.add(name: "Connection", value: "Upgrade")
    headers.add(name: "Sec-WebSocket-Version", value: "13")
    headers.add(name: "Sec-WebSocket-Key", value: validKey)
    headers.add(name: "Origin", value: ListenerUpgradePolicy.origin)
    headers.add(name: "Sec-WebSocket-Protocol", value: ListenerUpgradePolicy.subprotocol)
    mutate(&headers)
    return HTTPRequestHead(version: version, method: method, uri: uri, headers: headers)
  }
}

/// Encodes an allowlisted handshake envelope body for gate tests.
enum HandshakeFixture {
  static func envelope(kind: ListenerHandshakeKind, byteCount: Int = 32) throws -> Data {
    try ListenerHandshakeEnvelope(
      kind: kind,
      payload: Data(repeating: 0x01, count: byteCount)
    ).encoded()
  }
}
