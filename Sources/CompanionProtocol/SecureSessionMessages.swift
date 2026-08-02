import Foundation

/// Closed pairing-mode vocabulary. Phase 2 supports direct same-LAN pairing
/// only; unknown modes fail decoding closed.
public enum SecurePairingMode: String, Codable, CaseIterable, Sendable {
  case directLAN = "direct-lan"
}

/// First pairing message from the device. Carries the single-use bootstrap
/// secret from the QR; transcript signatures and SAS confirmation belong to
/// the Step 2.5 pairing state machine.
public struct SecurePairingRequest: Codable, Equatable, Sendable {
  public let pairingSessionID: UUID
  public let mode: SecurePairingMode
  public let endpointOrigin: String
  public let bootstrapSecret: Data
  public let deviceNonce: Data
  public let devicePublicKey: Data
  public let selection: SecureProtocolSelection

  public init(
    pairingSessionID: UUID,
    mode: SecurePairingMode,
    endpointOrigin: String,
    bootstrapSecret: Data,
    deviceNonce: Data,
    devicePublicKey: Data,
    selection: SecureProtocolSelection
  ) throws {
    try requireBoundedText(
      endpointOrigin,
      maxUTF8: SecureTransportLimits.maxEndpointOriginBytes,
      field: "endpointOrigin"
    )
    try requireExactByteCount(
      bootstrapSecret, SecureTransportLimits.bootstrapSecretByteCount, field: "bootstrapSecret")
    try requireExactByteCount(
      deviceNonce, SecureTransportLimits.nonceByteCount, field: "deviceNonce")
    try requireExactByteCount(
      devicePublicKey, SecureTransportLimits.publicKeyByteCount, field: "devicePublicKey")
    self.pairingSessionID = pairingSessionID
    self.mode = mode
    self.endpointOrigin = endpointOrigin
    self.bootstrapSecret = bootstrapSecret
    self.deviceNonce = deviceNonce
    self.devicePublicKey = devicePublicKey
    self.selection = selection
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      pairingSessionID: container.decode(UUID.self, forKey: .pairingSessionID),
      mode: container.decode(SecurePairingMode.self, forKey: .mode),
      endpointOrigin: container.decode(String.self, forKey: .endpointOrigin),
      bootstrapSecret: container.decode(Data.self, forKey: .bootstrapSecret),
      deviceNonce: container.decode(Data.self, forKey: .deviceNonce),
      devicePublicKey: container.decode(Data.self, forKey: .devicePublicKey),
      selection: container.decode(SecureProtocolSelection.self, forKey: .selection)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case pairingSessionID
    case mode
    case endpointOrigin
    case bootstrapSecret
    case deviceNonce
    case devicePublicKey
    case selection
  }
}

/// Host reply to a pairing request, echoing the exact accepted selection and
/// signing the pairing transcript with the long-term host identity.
public struct SecurePairingResponse: Codable, Equatable, Sendable {
  public let pairingSessionID: UUID
  public let hostID: UUID
  public let hostNonce: Data
  public let hostPublicKey: Data
  public let selection: SecureProtocolSelection
  public let transcriptSignature: Data

  public init(
    pairingSessionID: UUID,
    hostID: UUID,
    hostNonce: Data,
    hostPublicKey: Data,
    selection: SecureProtocolSelection,
    transcriptSignature: Data
  ) throws {
    try requireExactByteCount(hostNonce, SecureTransportLimits.nonceByteCount, field: "hostNonce")
    try requireExactByteCount(
      hostPublicKey, SecureTransportLimits.publicKeyByteCount, field: "hostPublicKey")
    try requireExactByteCount(
      transcriptSignature, SecureTransportLimits.signatureByteCount, field: "transcriptSignature")
    self.pairingSessionID = pairingSessionID
    self.hostID = hostID
    self.hostNonce = hostNonce
    self.hostPublicKey = hostPublicKey
    self.selection = selection
    self.transcriptSignature = transcriptSignature
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      pairingSessionID: container.decode(UUID.self, forKey: .pairingSessionID),
      hostID: container.decode(UUID.self, forKey: .hostID),
      hostNonce: container.decode(Data.self, forKey: .hostNonce),
      hostPublicKey: container.decode(Data.self, forKey: .hostPublicKey),
      selection: container.decode(SecureProtocolSelection.self, forKey: .selection),
      transcriptSignature: container.decode(Data.self, forKey: .transcriptSignature)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case pairingSessionID
    case hostID
    case hostNonce
    case hostPublicKey
    case selection
    case transcriptSignature
  }
}

/// Third and final pairing message, sent by the device after it verified the
/// host's transcript signature, derived the verification phrase, and received
/// its own local user confirmation.
///
/// It completes the mutual signing the pairing pair deliberately deferred:
/// the device signs exactly the same canonical pairing transcript the host
/// signed in ``SecurePairingResponse``. The device ID is a non-secret,
/// device-asserted identifier (threat model §3.3) — it is never proof of
/// identity, and uniqueness is decided by the Mac's grant authority.
public struct SecurePairingConfirmation: Codable, Equatable, Sendable {
  public let pairingSessionID: UUID
  public let deviceID: UUID
  public let transcriptSignature: Data

  public init(
    pairingSessionID: UUID,
    deviceID: UUID,
    transcriptSignature: Data
  ) throws {
    try requireExactByteCount(
      transcriptSignature, SecureTransportLimits.signatureByteCount, field: "transcriptSignature")
    self.pairingSessionID = pairingSessionID
    self.deviceID = deviceID
    self.transcriptSignature = transcriptSignature
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      pairingSessionID: container.decode(UUID.self, forKey: .pairingSessionID),
      deviceID: container.decode(UUID.self, forKey: .deviceID),
      transcriptSignature: container.decode(Data.self, forKey: .transcriptSignature)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case pairingSessionID
    case deviceID
    case transcriptSignature
  }
}

/// Session authentication request from a previously paired device.
public struct SecureSessionAuthRequest: Codable, Equatable, Sendable {
  public let deviceID: UUID
  public let selection: SecureProtocolSelection
  public let deviceEphemeralPublicKey: Data
  public let deviceNonce: Data
  public let transcriptSignature: Data

  public init(
    deviceID: UUID,
    selection: SecureProtocolSelection,
    deviceEphemeralPublicKey: Data,
    deviceNonce: Data,
    transcriptSignature: Data
  ) throws {
    try requireExactByteCount(
      deviceEphemeralPublicKey,
      SecureTransportLimits.publicKeyByteCount,
      field: "deviceEphemeralPublicKey"
    )
    try requireExactByteCount(
      deviceNonce, SecureTransportLimits.nonceByteCount, field: "deviceNonce")
    try requireExactByteCount(
      transcriptSignature, SecureTransportLimits.signatureByteCount, field: "transcriptSignature")
    self.deviceID = deviceID
    self.selection = selection
    self.deviceEphemeralPublicKey = deviceEphemeralPublicKey
    self.deviceNonce = deviceNonce
    self.transcriptSignature = transcriptSignature
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      deviceID: container.decode(UUID.self, forKey: .deviceID),
      selection: container.decode(SecureProtocolSelection.self, forKey: .selection),
      deviceEphemeralPublicKey: container.decode(Data.self, forKey: .deviceEphemeralPublicKey),
      deviceNonce: container.decode(Data.self, forKey: .deviceNonce),
      transcriptSignature: container.decode(Data.self, forKey: .transcriptSignature)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case deviceID
    case selection
    case deviceEphemeralPublicKey
    case deviceNonce
    case transcriptSignature
  }
}

/// Host reply completing session authentication. Binds the current Mac-stored
/// grant revision, authorized-view epoch, and host generation into the
/// session transcript.
public struct SecureSessionAuthResponse: Codable, Equatable, Sendable {
  public let sessionID: UUID
  public let selection: SecureProtocolSelection
  public let hostEphemeralPublicKey: Data
  public let hostNonce: Data
  public let grantRevision: UInt64
  public let authorizedViewEpoch: UInt64
  public let hostGeneration: UInt64
  public let transcriptSignature: Data

  public init(
    sessionID: UUID,
    selection: SecureProtocolSelection,
    hostEphemeralPublicKey: Data,
    hostNonce: Data,
    grantRevision: UInt64,
    authorizedViewEpoch: UInt64,
    hostGeneration: UInt64,
    transcriptSignature: Data
  ) throws {
    try requireExactByteCount(
      hostEphemeralPublicKey,
      SecureTransportLimits.publicKeyByteCount,
      field: "hostEphemeralPublicKey"
    )
    try requireExactByteCount(hostNonce, SecureTransportLimits.nonceByteCount, field: "hostNonce")
    try requireExactByteCount(
      transcriptSignature, SecureTransportLimits.signatureByteCount, field: "transcriptSignature")
    self.sessionID = sessionID
    self.selection = selection
    self.hostEphemeralPublicKey = hostEphemeralPublicKey
    self.hostNonce = hostNonce
    self.grantRevision = grantRevision
    self.authorizedViewEpoch = authorizedViewEpoch
    self.hostGeneration = hostGeneration
    self.transcriptSignature = transcriptSignature
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      sessionID: container.decode(UUID.self, forKey: .sessionID),
      selection: container.decode(SecureProtocolSelection.self, forKey: .selection),
      hostEphemeralPublicKey: container.decode(Data.self, forKey: .hostEphemeralPublicKey),
      hostNonce: container.decode(Data.self, forKey: .hostNonce),
      grantRevision: container.decode(UInt64.self, forKey: .grantRevision),
      authorizedViewEpoch: container.decode(UInt64.self, forKey: .authorizedViewEpoch),
      hostGeneration: container.decode(UInt64.self, forKey: .hostGeneration),
      transcriptSignature: container.decode(Data.self, forKey: .transcriptSignature)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case sessionID
    case selection
    case hostEphemeralPublicKey
    case hostNonce
    case grantRevision
    case authorizedViewEpoch
    case hostGeneration
    case transcriptSignature
  }
}

/// Observation subscription. A nil resume cursor requests a fresh filtered
/// snapshot; a present cursor is validated with `ReplayCursorEnvelope`.
public struct SecureObservationSubscribe: Codable, Equatable, Sendable {
  public let subscriptionID: UUID
  public let resumeCursor: ReplayCursorEnvelope?

  public init(subscriptionID: UUID, resumeCursor: ReplayCursorEnvelope?) {
    self.subscriptionID = subscriptionID
    self.resumeCursor = resumeCursor
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    self.init(
      subscriptionID: try container.decode(UUID.self, forKey: .subscriptionID),
      resumeCursor: try container.decodeIfPresent(ReplayCursorEnvelope.self, forKey: .resumeCursor)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case subscriptionID
    case resumeCursor
  }
}

/// Device acknowledgement of delivered observation data through a cursor.
public struct SecureObservationAcknowledgement: Codable, Equatable, Sendable {
  public let subscriptionID: UUID
  public let cursor: ReplayCursorEnvelope

  public init(subscriptionID: UUID, cursor: ReplayCursorEnvelope) {
    self.subscriptionID = subscriptionID
    self.cursor = cursor
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    self.init(
      subscriptionID: try container.decode(UUID.self, forKey: .subscriptionID),
      cursor: try container.decode(ReplayCursorEnvelope.self, forKey: .cursor)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case subscriptionID
    case cursor
  }
}

/// Closed delivery-kind vocabulary for observation payloads.
public enum SecureObservationDeliveryKind: String, Codable, CaseIterable, Sendable {
  case snapshot
  case event
}

/// Envelope delivering one already-filtered snapshot or event payload. The
/// payload is opaque bounded bytes; its content schema is bound by later
/// steps, keeping this envelope pure carriage.
public struct SecureObservationDelivery: Codable, Equatable, Sendable {
  public let subscriptionID: UUID
  public let kind: SecureObservationDeliveryKind
  public let cursor: ReplayCursorEnvelope
  public let payload: Data

  public init(
    subscriptionID: UUID,
    kind: SecureObservationDeliveryKind,
    cursor: ReplayCursorEnvelope,
    payload: Data
  ) throws {
    try requireByteCount(
      payload, in: 1...SecureTransportLimits.maxObservationPayloadBytes, field: "payload")
    self.subscriptionID = subscriptionID
    self.kind = kind
    self.cursor = cursor
    self.payload = payload
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      subscriptionID: container.decode(UUID.self, forKey: .subscriptionID),
      kind: container.decode(SecureObservationDeliveryKind.self, forKey: .kind),
      cursor: container.decode(ReplayCursorEnvelope.self, forKey: .cursor),
      payload: container.decode(Data.self, forKey: .payload)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case subscriptionID
    case kind
    case cursor
    case payload
  }
}

/// Closed terminal command outcomes.
public enum SecureCommandOutcome: String, Codable, CaseIterable, Sendable {
  case completed
  case denied
  case failed
  case outcomeUnknown
}

/// Closed, content-free denial vocabulary. No free-form diagnostic exists.
public enum SecureCommandDenialReason: String, Codable, CaseIterable, Sendable {
  case revokedDevice
  case capabilityMissing
  case projectNotAllowed
  case actionProfileTooRestrictive
  case staleCommand
  case runtimeUnavailable
  case ledgerUnavailable
  case unsupportedCommand
  case attachmentsUnsupported
  case approvalsUnsupported
  case duplicateMismatch
}

/// Terminal result for a gateway command. A denial reason is present exactly
/// when the outcome is `denied`.
public struct SecureCommandResult: Codable, Equatable, Sendable {
  public let commandID: UUID
  public let outcome: SecureCommandOutcome
  public let denialReason: SecureCommandDenialReason?

  public init(
    commandID: UUID,
    outcome: SecureCommandOutcome,
    denialReason: SecureCommandDenialReason?
  ) throws {
    guard (outcome == .denied) == (denialReason != nil) else {
      throw SecureWireValidationError.invalidField(name: "denialReason")
    }
    self.commandID = commandID
    self.outcome = outcome
    self.denialReason = denialReason
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      commandID: container.decode(UUID.self, forKey: .commandID),
      outcome: container.decode(SecureCommandOutcome.self, forKey: .outcome),
      denialReason: container.decodeIfPresent(SecureCommandDenialReason.self, forKey: .denialReason)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case commandID
    case outcome
    case denialReason
  }
}
