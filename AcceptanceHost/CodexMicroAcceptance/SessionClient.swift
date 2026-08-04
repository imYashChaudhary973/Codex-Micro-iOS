import CompanionCrypto
import CompanionProtocol
import Foundation

/// The phone's authenticated session: connect, authenticate, then exchange
/// sealed application messages.
///
/// Pairing and this are deliberately different connections. Pairing never
/// authenticates a socket — the device reconnects to authenticate, which is
/// what stops a pairing secret from also being a session credential.
///
/// **Every application message is sealed and counted.** The sealer and opener
/// come out of authentication holding directional keys and exactly-next
/// counters, so a replayed or reordered frame is rejected by the codec rather
/// than by any check written here. That is why this type never inspects a
/// counter: doing so would imply the codec might not.
public actor SessionClient {
  public enum Failure: Error, Equatable, Sendable {
    case notPaired
    case connectionFailed
    case authenticationFailed
    /// Authentication failed with a reason worth naming.
    ///
    /// The catch-all was hiding which step broke, which made a working
    /// transport and a rejected identity look identical from the phone.
    case authenticationRejected(String)
    case sessionClosed(SecureCloseReason)
    case malformedReply
    case notAuthenticated
  }

  private let host: PairedHost
  private let identity: SessionDeviceIdentity
  private var client: PairingClient?
  private var session: EstablishedDeviceSession?

  public init(host: PairedHost, identity: SessionDeviceIdentity) {
    self.host = host
    self.identity = identity
  }

  /// Whether an authenticated session is open.
  public var isAuthenticated: Bool { session != nil }

  /// The device identifier this session authenticates as.
  public nonisolated var deviceID: UUID { identity.deviceID }

  // MARK: - Authentication

  /// Connects and authenticates, leaving the socket open for application
  /// messages.
  ///
  /// The three-message flow runs on **one connection** because the host binds
  /// an in-flight handshake to the socket it arrived on — the same property
  /// that made the first physical pairing attempt fail when it used two.
  public func authenticate() async throws {
    let attempt: SessionDeviceAttempt
    do {
      attempt = try SessionDeviceEndpoint(
        identity: identity,
        hostID: host.hostID,
        hostPublicKeyX963: host.hostPublicKeyX963,
        hostTLSSPKIFingerprint: host.tlsSPKIFingerprint
      ).beginAuthentication()
    } catch {
      // Thrown before any network activity: either the pinned host key or the
      // stored fingerprint failed validation, or the protocol selection was
      // refused. Naming it matters because none of those is a network fault
      // and all three read as one from the screen.
      throw Failure.authenticationRejected("begin:\(type(of: error)):\(error)")
    }

    guard let origin = URL(string: host.endpointOrigin), let hostname = origin.host,
      let url = PairingClient.url(host: hostname, port: origin.port ?? 443)
    else {
      throw Failure.connectionFailed
    }

    let client = PairingClient(expectedSPKIFingerprint: host.tlsSPKIFingerprint)
    client.connect(to: url)
    self.client = client

    let reply: Data
    do {
      reply = try await client.exchange(
        ListenerHandshakeEnvelopeWire(
          kind: .sessionAuthRequest, payload: try JSONEncoder().encode(attempt.request)))
    } catch {
      client.close()
      self.client = nil
      throw Failure.connectionFailed
    }

    do {
      let envelope = try ListenerHandshakeEnvelopeWire.decode(reply)
      guard envelope.kind == .sessionAuthResponse else { throw Failure.malformedReply }
      let response = try JSONDecoder().decode(
        SecureSessionAuthResponse.self, from: envelope.payload)
      let completion = try attempt.completeAuthentication(with: response)
      // Message 3 proves freshness to the host. Until it lands the host has
      // committed nothing, so a session is not open until this send succeeds.
      try await client.send(
        ListenerHandshakeEnvelopeWire(
          kind: .sessionAuthConfirmation,
          payload: try JSONEncoder().encode(completion.confirmation)))
      session = completion.session
    } catch let reason as SessionClosedReason {
      client.close()
      self.client = nil
      throw Failure.sessionClosed(reason.closeReason(in: .authenticatedSession))
    } catch let failure as Failure {
      client.close()
      self.client = nil
      throw failure
    } catch {
      client.close()
      self.client = nil
      throw Failure.authenticationRejected("\(type(of: error)):\(error)")
    }
  }

  public func close() {
    client?.close()
    client = nil
    session = nil
  }

  // MARK: - Application messages

  /// Seals one application message and sends it.
  public func send(kind: ListenerApplicationEnvelopeWire.Kind, payload: Data) async throws {
    guard var open = session, let client else { throw Failure.notAuthenticated }
    let envelope = try ListenerApplicationEnvelopeWire(kind: kind, payload: payload)
    let sealed: Data
    do {
      sealed = try open.outbound.seal(try envelope.encoded())
    } catch {
      throw Failure.sessionClosed(.frameViolation)
    }
    // The sealer advances its counter on success, so the mutated copy must be
    // written back before the next send or the host sees a repeat.
    session = open
    try await client.sendRaw(sealed)
  }

  /// Receives and opens one application message.
  public func receive() async throws -> ListenerApplicationEnvelopeWire {
    guard var open = session, let client else { throw Failure.notAuthenticated }
    let sealed = try await client.receiveRaw()
    let body: Data
    do {
      body = try open.inbound.open(sealed)
    } catch {
      throw Failure.sessionClosed(.counterViolation)
    }
    session = open
    guard let envelope = try? ListenerApplicationEnvelopeWire.decode(body) else {
      throw Failure.malformedReply
    }
    guard !envelope.kind.isDeviceOriginated else {
      // A host that echoes a device-originated kind is not speaking this
      // protocol. Accepting it would let a confused host drive the phone.
      throw Failure.malformedReply
    }
    return envelope
  }
}
