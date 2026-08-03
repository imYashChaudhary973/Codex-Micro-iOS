import CompanionCrypto
import CompanionProtocol
import Foundation

/// The closed set of message kinds that may cross the listener before an
/// application session exists (plan §7 gate 2).
///
/// Only the four device-originated cases are ever accepted inbound; the
/// three host-originated cases exist so the same envelope carries replies.
/// Anything else — an unknown discriminator, a host-only kind arriving
/// inbound, an unparseable body, an oversized body, or any application
/// message — is refused with one content-neutral reason.
public enum ListenerHandshakeKind: String, Codable, CaseIterable, Sendable {
  /// Device → host: pairing message 1.
  case pairingRequest
  /// Host → device: pairing message 2.
  case pairingResponse
  /// Device → host: pairing message 3.
  case pairingConfirmation
  /// Device → host: authentication message 1.
  case sessionAuthRequest
  /// Host → device: authentication message 2.
  case sessionAuthResponse
  /// Device → host: authentication message 3.
  case sessionAuthConfirmation
  /// Host → device: the closed terminal reason.
  case closeNotice

  /// Whether a device may send this kind. This set **is** the
  /// pre-authentication allowlist.
  public var isDeviceOriginated: Bool {
    switch self {
    case .pairingRequest, .pairingConfirmation, .sessionAuthRequest, .sessionAuthConfirmation:
      return true
    case .pairingResponse, .sessionAuthResponse, .closeNotice:
      return false
    }
  }

  /// The per-source rate window this kind is charged against, or `nil` when
  /// it is not device-originated.
  ///
  /// Both pairing messages and both authentication messages are charged,
  /// because each one costs the host a signature verification. Charging only
  /// the first message of a flow left the rest free.
  public var sourceWindow: ListenerSourceWindow? {
    switch self {
    case .pairingRequest, .pairingConfirmation:
      return .pairing
    case .sessionAuthRequest, .sessionAuthConfirmation:
      return .authentication
    case .pairingResponse, .sessionAuthResponse, .closeNotice:
      return nil
    }
  }
}

/// The two per-source handshake rate windows.
public enum ListenerSourceWindow: String, Equatable, CaseIterable, Sendable {
  /// Charged against the ADR §9 per-source pairing ceiling.
  case pairing
  /// Charged against the per-source connection ceiling, since every
  /// authentication needs a connection anyway.
  case authentication
}

/// Transport framing for one pre-authentication message.
///
/// This is transport carriage, not application schema: it carries exactly a
/// closed discriminator and an opaque bounded body, so the listener can
/// enforce the allowlist without interpreting — or being able to disclose —
/// any application content. Decoding is strict: unknown fields, unknown
/// kinds, a missing body, and an oversized body all fail closed.
public struct ListenerHandshakeEnvelope: Codable, Equatable, Sendable {
  /// Maximum body size. Every pre-authentication message is a few hundred
  /// bytes of nonces, public keys, and signatures; this is a generous
  /// ceiling well inside the WebSocket message cap.
  public static let maxPayloadBytes = 4 * 1024

  /// The closed message discriminator.
  public let kind: ListenerHandshakeKind
  /// The opaque bounded body.
  public let payload: Data

  /// Creates an envelope, rejecting an empty or oversized body.
  public init(kind: ListenerHandshakeKind, payload: Data) throws {
    guard !payload.isEmpty, payload.count <= Self.maxPayloadBytes else {
      throw ListenerHandshakeRejection.malformed
    }
    self.kind = kind
    self.payload = payload
  }

  public init(from decoder: Decoder) throws {
    let allowed = Set(CodingKeys.allCases.map(\.stringValue))
    let dynamic = try decoder.container(keyedBy: ListenerDynamicCodingKey.self)
    guard Set(dynamic.allKeys.map(\.stringValue)).isSubset(of: allowed) else {
      throw ListenerHandshakeRejection.malformed
    }
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      kind: container.decode(ListenerHandshakeKind.self, forKey: .kind),
      payload: container.decode(Data.self, forKey: .payload)
    )
  }

  /// Encodes to the canonical JSON body the transport writes.
  ///
  /// Keys are sorted so two refusals for two different device states are
  /// byte-identical on the wire, which is what makes the collapsed
  /// pre-authentication reason actually indistinguishable.
  public func encoded() throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(self)
  }

  /// Decodes and validates a body received from a peer.
  public static func decode(_ data: Data) throws -> ListenerHandshakeEnvelope {
    guard data.count <= maxPayloadBytes * 2 else { throw ListenerHandshakeRejection.malformed }
    do {
      return try JSONDecoder().decode(ListenerHandshakeEnvelope.self, from: data)
    } catch let rejection as ListenerHandshakeRejection {
      throw rejection
    } catch {
      throw ListenerHandshakeRejection.malformed
    }
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case kind
    case payload
  }
}

/// The single content-neutral failure a malformed or disallowed
/// pre-authentication message produces. It carries no detail by design.
public enum ListenerHandshakeRejection: Error, Equatable, Sendable {
  /// The message was not exactly one well-formed allowlisted envelope.
  case malformed
}

struct ListenerDynamicCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil

  init?(stringValue: String) {
    self.stringValue = stringValue
  }

  init?(intValue: Int) {
    return nil
  }
}

/// The pre-authentication decision for one inbound message.
public enum ListenerPreAuthDecision: Equatable, Sendable {
  /// The message is an allowlisted device-originated handshake message.
  case allowed(ListenerHandshakeEnvelope)
  /// The message is refused with the single collapsed reason.
  case refused(SecureCloseReason)
}

/// The closed pre-authentication allowlist (plan §7 gate 2).
///
/// Before authentication completes a connection may carry only the four
/// device-originated handshake kinds. Everything else is refused with the
/// single collapsed reason, and no thread, project, Codex, grant, journal,
/// or device-existence signal is ever produced.
///
/// **Exactly one reason, enforced at the gate.** A malformed body, an
/// application message, a host-only kind, an exhausted per-source ceiling, a
/// failed pairing, and a failed authentication all close with
/// ``collapsedRefusal``. The per-source ceiling matters most: it is
/// evaluated before any coordinator is consulted and its counter is shared
/// by every peer behind one source address, so a distinct rate-limited
/// reason would let one device learn that another behind the same address
/// recently attempted pairing. Specific reasons resume only after a peer has
/// authenticated, where the reason is about a device that has proven it is
/// that device.
public struct ListenerPreAuthAllowlist: Sendable {
  /// The exact inbound allowlist.
  public static var allowedInboundKinds: Set<ListenerHandshakeKind> {
    Set(ListenerHandshakeKind.allCases.filter(\.isDeviceOriginated))
  }

  /// The one reason every pre-authentication refusal carries.
  public static let collapsedRefusal = SecureCloseReason.authenticationFailed

  /// Creates the allowlist. It holds no state.
  public init() {}

  /// Classifies one inbound pre-authentication message.
  public func classify(_ payload: Data) -> ListenerPreAuthDecision {
    guard let envelope = try? ListenerHandshakeEnvelope.decode(payload),
      envelope.kind.isDeviceOriginated
    else {
      return .refused(Self.collapsedRefusal)
    }
    return .allowed(envelope)
  }
}

/// What the handshake seam decided about one allowlisted message.
public enum ListenerHandshakeOutcome: Sendable {
  /// Send this reply and stay unauthenticated.
  case reply(ListenerHandshakeEnvelope)
  /// Promote the connection to authenticated, optionally sending a final
  /// handshake reply first. Post-authentication traffic is sealed and is
  /// Step 2.8's to deliver, so this step normally carries no reply.
  case authenticated(reply: ListenerHandshakeEnvelope?, session: AuthenticatedSessionIdentity)
  /// Close with this closed reason. Pre-authentication reasons are already
  /// collapsed upstream.
  case close(SecureCloseReason)
}

/// The seam through which the listener reaches the transport-independent
/// pairing and authentication state machines.
///
/// `MacBridgeServer` owns the transport; it owns no grants, journal, or
/// command policy. This protocol is the whole surface between them: the
/// listener hands over an allowlisted envelope and receives a reply, a
/// promotion, or a closed reason.
public protocol ListenerHandshakeHandling: Sendable {
  /// Handles one allowlisted device-originated message for a connection.
  func handle(
    _ envelope: ListenerHandshakeEnvelope,
    connectionID: UUID
  ) async -> ListenerHandshakeOutcome

  /// Releases any in-flight handshake state for a closed connection.
  func abandon(connectionID: UUID) async
}

/// The fail-closed default: every pre-authentication message is refused.
///
/// This is what an unconfigured listener uses, so a listener that somehow
/// starts without a wired handshake seam authenticates nobody rather than
/// admitting anybody.
public struct DenyingListenerHandshakeHandler: ListenerHandshakeHandling {
  /// Creates the denying handler.
  public init() {}

  public func handle(
    _ envelope: ListenerHandshakeEnvelope,
    connectionID: UUID
  ) async -> ListenerHandshakeOutcome {
    .close(.authenticationFailed)
  }

  public func abandon(connectionID: UUID) async {}
}

/// Wires the listener to the Step 2.5 pairing state machine and the Step 2.6
/// authenticated-session state machine.
///
/// The transport contributes only carriage and bounds. Every authorization
/// decision stays inside the coordinators, and every rejection they produce
/// is already collapsed onto one closed reason, so nothing here can widen
/// the pre-authentication disclosure surface.
///
/// Pairing never authenticates a connection: a paired device reconnects and
/// authenticates through the session coordinator, exactly as the plan's
/// dependency chain requires.
public struct CoordinatorListenerHandshakeHandler: ListenerHandshakeHandling {
  private let pairing: PairingCoordinator?
  private let session: SessionCoordinator
  private let frames: ListenerSessionFrameRegistry

  /// Creates the handler.
  ///
  /// - Parameters:
  ///   - pairing: The pairing coordinator, or `nil` when no pairing session
  ///     may be claimed. A `nil` coordinator refuses every pairing message.
  ///   - session: The authenticated-session coordinator.
  ///   - frames: Where a completed authentication's directional codecs wait
  ///     until the connection that authenticated claims them. Ownership
  ///     transfers exactly once, because their counters must never be
  ///     advanced from two places.
  public init(
    pairing: PairingCoordinator?,
    session: SessionCoordinator,
    frames: ListenerSessionFrameRegistry = ListenerSessionFrameRegistry()
  ) {
    self.pairing = pairing
    self.session = session
    self.frames = frames
  }

  /// The registry a listener wires to its observation handler.
  public var frameRegistry: ListenerSessionFrameRegistry { frames }

  public func handle(
    _ envelope: ListenerHandshakeEnvelope,
    connectionID: UUID
  ) async -> ListenerHandshakeOutcome {
    switch envelope.kind {
    case .pairingRequest:
      return await handlePairingRequest(envelope.payload)
    case .pairingConfirmation:
      return await handlePairingConfirmation(envelope.payload)
    case .sessionAuthRequest:
      return await handleAuthRequest(envelope.payload, connectionID: connectionID)
    case .sessionAuthConfirmation:
      return await handleAuthConfirmation(envelope.payload, connectionID: connectionID)
    case .pairingResponse, .sessionAuthResponse, .closeNotice:
      return .close(.protocolViolation)
    }
  }

  public func abandon(connectionID: UUID) async {
    await session.abandonHandshake(connectionID: connectionID)
    await frames.discardFrames(connectionID: connectionID)
  }

  private func handlePairingRequest(_ payload: Data) async -> ListenerHandshakeOutcome {
    guard let pairing,
      let request = try? JSONDecoder().decode(SecurePairingRequest.self, from: payload),
      let acceptance = try? await pairing.claim(request: request),
      let body = try? JSONEncoder().encode(acceptance.response),
      let reply = try? ListenerHandshakeEnvelope(kind: .pairingResponse, payload: body)
    else {
      return .close(.pairingFailed)
    }
    return .reply(reply)
  }

  private func handlePairingConfirmation(_ payload: Data) async -> ListenerHandshakeOutcome {
    guard let pairing,
      let confirmation = try? JSONDecoder().decode(SecurePairingConfirmation.self, from: payload),
      (try? await pairing.submitDeviceConfirmation(confirmation)) != nil
    else {
      return .close(.pairingFailed)
    }
    // Pairing completion still needs the Mac user's local confirmation and
    // never authenticates this connection; the device reconnects to
    // authenticate. The transport closes with the same collapsed reason it
    // uses for failure, so success and failure are indistinguishable here.
    return .close(.pairingFailed)
  }

  private func handleAuthRequest(
    _ payload: Data,
    connectionID: UUID
  ) async -> ListenerHandshakeOutcome {
    guard let request = try? JSONDecoder().decode(SecureSessionAuthRequest.self, from: payload),
      let offer = try? await session.beginAuthentication(
        request: request, connectionID: connectionID),
      let body = try? JSONEncoder().encode(offer.response),
      let reply = try? ListenerHandshakeEnvelope(kind: .sessionAuthResponse, payload: body)
    else {
      return .close(.authenticationFailed)
    }
    return .reply(reply)
  }

  private func handleAuthConfirmation(
    _ payload: Data,
    connectionID: UUID
  ) async -> ListenerHandshakeOutcome {
    guard
      let confirmation = try? JSONDecoder().decode(
        SecureSessionAuthConfirmation.self, from: payload),
      let authentication = try? await session.completeAuthentication(
        confirmation: confirmation, connectionID: connectionID)
    else {
      return .close(.authenticationFailed)
    }
    await frames.store(
      ListenerSessionFrames(
        deviceID: authentication.session.identity.deviceID,
        sessionID: authentication.session.identity.sessionID,
        inbound: authentication.session.inbound,
        outbound: authentication.session.outbound
      ),
      connectionID: connectionID
    )
    return .authenticated(reply: nil, session: authentication.session.identity)
  }
}
