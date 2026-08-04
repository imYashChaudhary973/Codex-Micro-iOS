import CompanionCrypto
import CompanionProtocol
import Foundation

/// The closed set of message kinds that may cross an **authenticated**
/// connection.
///
/// This is the post-authentication counterpart of
/// ``ListenerHandshakeKind``, and it is deliberately just as narrow: three
/// device-originated kinds, the subscription, its acknowledgement, and one
/// opaque command envelope.
///
/// The command envelope carries a `ClientCommand` the transport never
/// interprets. Which commands are permitted is decided entirely by the
/// gateway's own allowlist behind the seam — the transport has no
/// per-command kind to widen, so no future wire change here can enable a
/// command the gateway has not accepted (plan §2 invariant 12).
public enum ListenerApplicationKind: String, Codable, CaseIterable, Sendable {
  /// Device → host: open or resume an observation subscription.
  case observationSubscribe
  /// Device → host: acknowledge delivered data through a cursor.
  case observationAcknowledge
  /// Device → host: one semantic mutation for the command gateway.
  case commandRequest
  /// Host → device: one already-authorized snapshot or event batch.
  case observationDelivery
  /// Host → device: the terminal result of one command.
  case commandResult
  /// Host → device: the closed terminal reason.
  case closeNotice

  /// Whether a device may send this kind. This set **is** the
  /// post-authentication inbound allowlist.
  public var isDeviceOriginated: Bool {
    switch self {
    case .observationSubscribe, .observationAcknowledge, .commandRequest: return true
    case .observationDelivery, .commandResult, .closeNotice: return false
    }
  }
}

/// Transport framing for one post-authentication message.
///
/// Carriage only, exactly like ``ListenerHandshakeEnvelope``: a closed
/// discriminator plus an opaque bounded body. It travels **inside** an AEAD
/// frame, so it is never visible on the wire — TLS is not the authorization
/// layer and this envelope is not the confidentiality layer (plan §2
/// invariant 9).
public struct ListenerApplicationEnvelope: Codable, Equatable, Sendable {
  /// Maximum body size, sized so a maximal observation payload plus its
  /// envelope and cursor still fits one sealed frame.
  public static let maxPayloadBytes = SecureTransportLimits.maxObservationPayloadBytes + 2 * 1024

  public let kind: ListenerApplicationKind
  public let payload: Data

  public init(kind: ListenerApplicationKind, payload: Data) throws {
    guard !payload.isEmpty, payload.count <= Self.maxPayloadBytes else {
      throw ListenerApplicationRejection.malformed
    }
    self.kind = kind
    self.payload = payload
  }

  public init(from decoder: Decoder) throws {
    let allowed = Set(CodingKeys.allCases.map(\.stringValue))
    let dynamic = try decoder.container(keyedBy: ListenerDynamicCodingKey.self)
    guard Set(dynamic.allKeys.map(\.stringValue)).isSubset(of: allowed) else {
      throw ListenerApplicationRejection.malformed
    }
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      kind: container.decode(ListenerApplicationKind.self, forKey: .kind),
      payload: container.decode(Data.self, forKey: .payload)
    )
  }

  /// Encodes to the canonical JSON body that is then sealed.
  public func encoded() throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(self)
  }

  /// Decodes and validates a plaintext body opened from a sealed frame.
  public static func decode(_ data: Data) throws -> ListenerApplicationEnvelope {
    guard data.count <= maxPayloadBytes * 2 else { throw ListenerApplicationRejection.malformed }
    do {
      return try JSONDecoder().decode(ListenerApplicationEnvelope.self, from: data)
    } catch let rejection as ListenerApplicationRejection {
      throw rejection
    } catch {
      throw ListenerApplicationRejection.malformed
    }
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case kind
    case payload
  }
}

/// The single content-neutral failure a malformed or disallowed
/// post-authentication message produces.
public enum ListenerApplicationRejection: Error, Equatable, Sendable {
  case malformed
}

/// One already-authorized observation batch as the transport sees it.
///
/// Every value inside has already been filtered against the device's current
/// Mac-stored scope by `MacBridgeCore`. The transport never filters, never
/// sees an unfiltered journal, and never learns why something is absent
/// (plan §9 ownership).
public enum ListenerObservationPayload: Equatable, Sendable {
  case snapshot(SecureObservationSnapshot)
  case events(SecureObservationEventBatch)

  var deliveryKind: SecureObservationDeliveryKind {
    switch self {
    case .snapshot: .snapshot
    case .events: .event
    }
  }

  func encoded() throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    switch self {
    case .snapshot(let snapshot): return try encoder.encode(snapshot)
    case .events(let batch): return try encoder.encode(batch)
    }
  }
}

/// One batch plus the cursor the device must echo to acknowledge it.
public struct ListenerObservationBatch: Equatable, Sendable {
  public let payload: ListenerObservationPayload
  public let cursor: ReplayCursorEnvelope

  public init(payload: ListenerObservationPayload, cursor: ReplayCursorEnvelope) {
    self.payload = payload
    self.cursor = cursor
  }
}

/// Closed refusals the observation seam may return.
///
/// These are **post-authentication** reasons, so they may be specific: the
/// peer has already proven it is the device the reason is about (threat model
/// §8). They map onto the closed wire vocabulary and carry no content.
public enum ListenerObservationRefusal: Error, Equatable, Sendable {
  /// The device holds no live grant with observation rights.
  case notAuthorized
  /// The grant authority could not be read, so nothing is disclosed.
  case authorityUnavailable
  /// A presented cursor failed closed rather than resynchronizing.
  case cursorRejected
  /// The message did not fit the post-authentication contract.
  case protocolViolation

  /// The closed wire close code for this refusal.
  public var closeReason: SecureCloseReason {
    switch self {
    case .notAuthorized: .deviceRevoked
    case .authorityUnavailable: .authorizationChanged
    case .cursorRejected: .counterViolation
    case .protocolViolation: .protocolViolation
    }
  }
}

/// The whole surface between the transport and the Step 2.8 observation
/// broker.
///
/// `MacBridgeServer` owns connections and sealed carriage; it owns no
/// journal, scope, or cursor authority. Everything it can obtain arrives
/// through this protocol already filtered, so the executor-bypass seam holds:
/// this module still does not import `MacBridgeCore`.
public protocol ListenerObservationHandling: Sendable {
  /// Opens or resumes the device's subscription and returns its first batch.
  func subscribe(
    deviceID: UUID,
    subscriptionID: UUID,
    resumeCursor: ReplayCursorEnvelope?
  ) async throws -> ListenerObservationBatch

  /// The next batch for a device, or `nil` when it is caught up or
  /// back-pressured.
  func nextBatch(deviceID: UUID) async throws -> ListenerObservationBatch?

  /// Records the device's acknowledgement.
  func acknowledge(
    deviceID: UUID,
    subscriptionID: UUID,
    cursor: ReplayCursorEnvelope
  ) async throws

  /// Releases subscription state for a closed connection.
  func release(deviceID: UUID) async
}

/// The fail-closed default: an unconfigured listener discloses nothing.
///
/// A listener that somehow reaches the authenticated state without a wired
/// observation seam refuses every subscription rather than inventing data.
public struct DenyingListenerObservationHandler: ListenerObservationHandling {
  public init() {}

  public func subscribe(
    deviceID: UUID,
    subscriptionID: UUID,
    resumeCursor: ReplayCursorEnvelope?
  ) async throws -> ListenerObservationBatch {
    throw ListenerObservationRefusal.notAuthorized
  }

  public func nextBatch(deviceID: UUID) async throws -> ListenerObservationBatch? {
    throw ListenerObservationRefusal.notAuthorized
  }

  public func acknowledge(
    deviceID: UUID,
    subscriptionID: UUID,
    cursor: ReplayCursorEnvelope
  ) async throws {
    throw ListenerObservationRefusal.notAuthorized
  }

  public func release(deviceID: UUID) async {}
}

/// The directional frame codecs and device identity of one authenticated
/// connection.
///
/// Ownership transfers exactly once. The codecs carry per-direction counters
/// that must never be advanced from two places, so the provider hands them
/// over and forgets them rather than lending a copy.
public struct ListenerSessionFrames: Sendable {
  public let deviceID: UUID
  /// The authenticated session these codecs belong to. The gateway needs it
  /// to confirm the session is still the device's current one, and it comes
  /// from authentication rather than from any message.
  public let sessionID: UUID
  public var inbound: SecureFrameOpener
  public var outbound: SecureFrameSealer

  public init(
    deviceID: UUID,
    sessionID: UUID,
    inbound: SecureFrameOpener,
    outbound: SecureFrameSealer
  ) {
    self.deviceID = deviceID
    self.sessionID = sessionID
    self.inbound = inbound
    self.outbound = outbound
  }
}

extension ListenerSessionFrames: CustomStringConvertible, CustomReflectable {
  /// Redacted: it holds both directional frame keys.
  public var description: String { "ListenerSessionFrames(redacted)" }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// Hands the sealed-frame codecs of a completed authentication to the
/// connection that authenticated.
public protocol ListenerSessionFrameProviding: Sendable {
  /// Transfers ownership of the connection's codecs, or returns `nil` when no
  /// authenticated session exists for it. A second call returns `nil`.
  func takeFrames(connectionID: UUID) async -> ListenerSessionFrames?

  /// Discards any codecs still held for a closed connection.
  func discardFrames(connectionID: UUID) async
}

/// The fail-closed default: no connection ever receives frame codecs.
public struct DenyingListenerSessionFrameProvider: ListenerSessionFrameProviding {
  public init() {}

  public func takeFrames(connectionID: UUID) async -> ListenerSessionFrames? { nil }

  public func discardFrames(connectionID: UUID) async {}
}

/// Holds the directional codecs of a completed authentication until the
/// connection that authenticated takes ownership of them.
///
/// The handshake seam produces the codecs; the connection consumes them
/// exactly once. Nothing here is durable — a bridge restart drops every
/// pending set, exactly as it drops every session.
public actor ListenerSessionFrameRegistry: ListenerSessionFrameProviding {
  private var pending: [UUID: ListenerSessionFrames] = [:]

  public init() {}

  /// Records the codecs a completed authentication produced.
  public func store(_ frames: ListenerSessionFrames, connectionID: UUID) {
    pending[connectionID] = frames
  }

  public func takeFrames(connectionID: UUID) -> ListenerSessionFrames? {
    return pending.removeValue(forKey: connectionID)
  }

  public func discardFrames(connectionID: UUID) {
    pending.removeValue(forKey: connectionID)
  }

  /// How many completed authentications are still waiting to be claimed.
  public var pendingCount: Int { pending.count }
}
