import CompanionCrypto
import CryptoKit
import Foundation
import Security

/// One open pinned connection, handed to
/// ``PinnedProbeWebSocketClient/withConnection(url:_:)``.
///
/// It exists so a multi-message handshake stays on a single transport
/// connection, which is what the host binds in-flight handshake state to.
public struct PinnedProbeConnection: Sendable {
  private let task: URLSessionWebSocketTask

  init(task: URLSessionWebSocketTask) {
    self.task = task
  }

  /// Sends one binary application message.
  public func send(_ data: Data) async throws {
    try await task.send(.data(data))
  }

  /// Receives the next binary message. A text message is a policy violation.
  public func receive() async throws -> Data {
    switch try await task.receive() {
    case .data(let response):
      return response
    case .string:
      throw PinnedProbeClientError.invalidMessage
    @unknown default:
      throw PinnedProbeClientError.invalidMessage
    }
  }
}

/// Closed pinned-client failure vocabulary.
///
/// ``pinMismatch`` is surfaced exactly, rather than as a generic URLSession
/// error, so a test — and the Step 2.14 acceptance matrix — can prove the
/// pin decided the outcome (ADR §5).
public enum PinnedProbeClientError: Error, Equatable, Sendable {
  /// The peer presented a certificate whose SPKI is not the pinned one.
  case pinMismatch
  /// No usable server trust or public key was presented.
  case trustUnavailable
  /// The exchange did not complete inside the client deadline.
  case timeout
  /// A text message arrived; the transport is binary-only.
  case invalidMessage
  /// The peer closed without completing the exchange.
  case closed
}

/// The deterministic SPKI-pinned WSS client (ADR §4).
///
/// It performs **no** CA or system trust evaluation: trust is exactly the
/// SPKI fingerprint supplied at construction, which comes from pairing or a
/// verified rotation statement. It is the loopback/acceptance client — the
/// iOS product client is Phase 3 — and it is used by the Step 2.7
/// integration tests and the Step 2.14 acceptance tooling.
///
/// `URLSessionWebSocketTask` offers `permessage-deflate` with no public
/// suppression switch; the server tolerates exactly that offer and omits it
/// from the response, so compression is never negotiated (ADR §9).
public final class PinnedProbeWebSocketClient: NSObject, URLSessionDelegate, @unchecked Sendable {
  private enum Failure: Equatable, Sendable {
    case none
    case pinMismatch
    case trustUnavailable
    case timeout
  }

  private let expectedSPKIFingerprint: Data
  private let deadline: Duration
  private let lock = NSLock()
  private var failure = Failure.none
  private lazy var session = URLSession(
    configuration: .ephemeral,
    delegate: self,
    delegateQueue: nil
  )

  /// Creates a client pinned to `expectedSPKIFingerprint` (SHA-256 of the
  /// SubjectPublicKeyInfo DER).
  public init(expectedSPKIFingerprint: Data, deadline: Duration = .seconds(5)) {
    self.expectedSPKIFingerprint = expectedSPKIFingerprint
    self.deadline = deadline
    super.init()
  }

  /// The `wss://` URL for a listener endpoint, on the exact policy path.
  public static func url(for endpoint: ListenerEndpoint) -> URL? {
    let host = endpoint.host.contains(":") ? "[\(endpoint.host)]" : endpoint.host
    return URL(string: "wss://\(host):\(endpoint.port)\(ListenerUpgradePolicy.path)")
  }

  /// Opens a pinned connection, sends `messages` in order, and returns the
  /// replies received before the peer stops answering or the deadline
  /// elapses.
  ///
  /// `expectedReplies` defaults to one reply per message. A smaller value
  /// sends the trailing messages without waiting — the shape of a handshake
  /// whose last message the host does not answer. A larger value keeps the
  /// connection open until the deadline, which the connection-cap tests use.
  ///
  /// The request carries exactly the required `Origin` and subprotocol; no
  /// other application header is set.
  public func exchange(
    url: URL,
    messages: [Data],
    expectedReplies: Int? = nil
  ) async throws -> [Data] {
    let replyBudget = expectedReplies ?? messages.count
    return try await withConnection(url: url) { connection in
      var replies: [Data] = []
      for message in messages {
        try await connection.send(message)
        guard replies.count < replyBudget else { continue }
        replies.append(try await connection.receive())
      }
      while replies.count < replyBudget {
        replies.append(try await connection.receive())
      }
      return replies
    }
  }

  /// Opens one pinned connection and runs `body` against it.
  ///
  /// Multi-message handshakes need a single connection, because the host
  /// binds an in-flight handshake to the transport connection it arrived on.
  /// The connection is always cancelled and the session invalidated when
  /// `body` returns or throws.
  public func withConnection<T>(
    url: URL,
    _ body: (PinnedProbeConnection) async throws -> T
  ) async throws -> T {
    var request = URLRequest(url: url)
    request.timeoutInterval = Double(deadline.components.seconds)
    request.setValue(ListenerUpgradePolicy.origin, forHTTPHeaderField: "Origin")
    request.setValue(
      ListenerUpgradePolicy.subprotocol,
      forHTTPHeaderField: "Sec-WebSocket-Protocol"
    )
    request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")

    let task = session.webSocketTask(with: request)
    task.resume()
    defer {
      task.cancel(with: .normalClosure, reason: nil)
      session.invalidateAndCancel()
    }
    let timeoutTask = Task { [weak self] in
      try await Task.sleep(for: self?.deadline ?? .seconds(5))
      self?.recordFailure(.timeout)
      task.cancel(with: .goingAway, reason: nil)
    }
    defer { timeoutTask.cancel() }

    do {
      return try await body(PinnedProbeConnection(task: task))
    } catch {
      throw mapped(error)
    }
  }

  /// Sends one message and returns the single reply.
  public func exchange(url: URL, message: Data) async throws -> Data {
    guard let reply = try await exchange(url: url, messages: [message]).first else {
      throw PinnedProbeClientError.closed
    }
    return reply
  }

  /// Opens a pinned connection and sends `message` without waiting for a
  /// reply. Used to prove that a rejected request closes without disclosing
  /// anything.
  public func send(url: URL, message: Data) async throws {
    _ = try await exchange(url: url, messages: [message])
  }

  /// Issues a plain (non-upgrade) HTTP request over the same pinned TLS
  /// connection, optionally with a body.
  ///
  /// NIO consults the upgrade policy only when an `Upgrade` header is
  /// present, so this is how a peer reaches the listener without ever
  /// touching ``ListenerUpgradePolicy``. It exists so tests — and the Step
  /// 2.14 acceptance matrix — can prove that path is still bounded.
  public func probeNonUpgradeRequest(
    url: URL,
    method: String = "GET",
    body: Data? = nil
  ) async throws {
    var request = URLRequest(url: url)
    request.httpMethod = method
    request.timeoutInterval = Double(deadline.components.seconds)
    request.httpBody = body
    do {
      _ = try await session.data(for: request)
    } catch {
      throw mapped(error)
    }
  }

  public func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler:
      @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      let trust = challenge.protectionSpace.serverTrust,
      let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
      let certificate = chain.first,
      let publicKey = SecCertificateCopyKey(certificate),
      let x963 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
      let spkiDER = try? SPKIFingerprint.subjectPublicKeyInfoDER(x963PublicKey: x963)
    else {
      recordFailure(.trustUnavailable)
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    let presented = Data(SHA256.hash(data: spkiDER))
    guard constantTimeMatches(presented, expectedSPKIFingerprint) else {
      recordFailure(.pinMismatch)
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }

  private func mapped(_ error: any Error) -> any Error {
    switch lock.withLock({ failure }) {
    case .pinMismatch:
      return PinnedProbeClientError.pinMismatch
    case .trustUnavailable:
      return PinnedProbeClientError.trustUnavailable
    case .timeout:
      return PinnedProbeClientError.timeout
    case .none:
      return error
    }
  }

  private func recordFailure(_ failure: Failure) {
    lock.withLock {
      guard self.failure == .none else { return }
      self.failure = failure
    }
  }

  private func constantTimeMatches(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for (left, right) in zip(lhs, rhs) {
      difference |= left ^ right
    }
    return difference == 0
  }
}
