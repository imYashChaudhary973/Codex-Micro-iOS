import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation

/// The phone's pinned WSS client for pairing.
///
/// **It pins the SPKI the QR carried, and nothing else.** There is no CA, no
/// hostname check worth trusting on a LAN address, and no fallback: the Mac
/// serves a self-signed certificate whose key the QR named, so the only
/// question at TLS time is whether the presented key hashes to that value.
/// A mismatch cancels the challenge, which is what makes a
/// machine-in-the-middle on the same Wi-Fi a connection failure rather than a
/// silent interception.
///
/// Certificate *bytes* are deliberately not pinned. Same-key renewal happens
/// every twenty days or so (ADR §7), and a phone that pinned bytes would break
/// on every renewal for no security gain.
public final class PairingClient: NSObject, URLSessionDelegate, @unchecked Sendable {
  /// Closed failure vocabulary. Nothing here carries an address or a key.
  public enum Failure: Error, Equatable, Sendable {
    /// The presented key did not hash to the pinned SPKI. Treat as hostile.
    case pinMismatch
    /// Server trust was unavailable or unreadable.
    case trustUnavailable
    /// The socket closed before the exchange completed.
    case connectionClosed
    /// The host replied with something that is not a handshake envelope.
    case malformedReply
    /// The host refused the pairing.
    case refused
  }

  private let expectedSPKIFingerprint: Data
  private let lock = NSLock()
  private var pinFailure: Failure?
  private var session: URLSession?
  private var task: URLSessionWebSocketTask?

  public init(expectedSPKIFingerprint: Data) {
    self.expectedSPKIFingerprint = expectedSPKIFingerprint
    super.init()
  }

  /// Opens the pinned socket. The URL comes from the QR's endpoint origin, so
  /// the phone never guesses an address.
  public func connect(to url: URL) {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 10
    let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    self.session = session
    let task = session.webSocketTask(with: url)
    self.task = task
    task.resume()
  }

  public func close() {
    task?.cancel(with: .goingAway, reason: nil)
    session?.invalidateAndCancel()
    task = nil
    session = nil
  }

  /// Sends one handshake envelope and waits for the reply.
  ///
  /// Envelopes are binary frames because that is what the listener's frame
  /// policy admits; a text frame is a protocol violation there, not a
  /// tolerated variant.
  public func exchange(_ envelope: ListenerHandshakeEnvelopeWire) async throws -> Data {
    guard let task else { throw Failure.connectionClosed }
    try await task.send(.data(try envelope.encoded()))
    let message: URLSessionWebSocketTask.Message
    do {
      message = try await task.receive()
    } catch {
      throw lock.withLock { pinFailure } ?? Failure.connectionClosed
    }
    switch message {
    case .data(let data): return data
    case .string: throw Failure.malformedReply
    @unknown default: throw Failure.malformedReply
    }
  }

  /// Sends one envelope without expecting a reply. The confirmation message is
  /// like this: the host closes the connection either way, so waiting for a
  /// reply would only ever time out.
  public func send(_ envelope: ListenerHandshakeEnvelopeWire) async throws {
    guard let task else { throw Failure.connectionClosed }
    try await task.send(.data(try envelope.encoded()))
  }

  // MARK: - Pinning

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
      record(.trustUnavailable)
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    let presented = Data(SHA256.hash(data: spkiDER))
    guard Self.constantTimeMatches(presented, expectedSPKIFingerprint) else {
      record(.pinMismatch)
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }

  private func record(_ failure: Failure) {
    lock.withLock {
      guard pinFailure == nil else { return }
      pinFailure = failure
    }
  }

  /// Comparison is constant-time out of habit rather than necessity — the
  /// fingerprint is public — because a digest comparison that is sometimes
  /// variable-time is a pattern that gets copied to somewhere it matters.
  static func constantTimeMatches(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for (left, right) in zip(lhs, rhs) {
      difference |= left ^ right
    }
    return difference == 0
  }
}

/// The wire form of a handshake envelope, mirrored on the phone.
///
/// `ListenerHandshakeEnvelope` lives in `MacBridgeServer`, which is macOS-only
/// and imports NIO. The phone needs the same two fields and the same bound,
/// so it restates them rather than pulling a server transport target onto iOS.
/// The kind strings are the contract; a divergence here is a closed
/// `protocolViolation` at the listener rather than a silent mismatch.
public struct ListenerHandshakeEnvelopeWire: Codable, Equatable, Sendable {
  /// Must match `ListenerHandshakeKind` on the Mac.
  public enum Kind: String, Codable, Sendable {
    case pairingRequest
    case pairingResponse
    case pairingConfirmation
    case sessionAuthRequest
    case sessionAuthResponse
    case closeNotice
  }

  /// Matches `ListenerHandshakeEnvelope.maxPayloadBytes`.
  public static let maxPayloadBytes = 4 * 1024

  public let kind: Kind
  public let payload: Data

  public init(kind: Kind, payload: Data) throws {
    guard payload.count <= Self.maxPayloadBytes else {
      throw PairingClient.Failure.malformedReply
    }
    self.kind = kind
    self.payload = payload
  }

  public func encoded() throws -> Data {
    try JSONEncoder().encode(self)
  }

  public static func decode(_ data: Data) throws -> ListenerHandshakeEnvelopeWire {
    guard data.count <= maxPayloadBytes * 2 else {
      throw PairingClient.Failure.malformedReply
    }
    return try JSONDecoder().decode(ListenerHandshakeEnvelopeWire.self, from: data)
  }
}
