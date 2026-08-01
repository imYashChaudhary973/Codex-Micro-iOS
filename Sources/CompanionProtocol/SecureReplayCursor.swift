import Foundation

/// The 128-bit journal epoch minted fresh on every bridge-process start.
/// Modeled as exactly 16 raw bytes; any other length fails closed.
public struct JournalEpoch: Codable, Equatable, Hashable, Sendable {
  public let rawBytes: Data

  public init(rawBytes: Data) throws {
    try requireExactByteCount(
      rawBytes,
      SecureTransportLimits.journalEpochByteCount,
      field: "journalEpoch"
    )
    self.rawBytes = rawBytes
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    try self.init(rawBytes: container.decode(Data.self))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(rawBytes)
  }
}

/// The sealed replay cursor envelope fixed by the Phase 2 plan (§9):
/// `(deviceID, grantRevision, authorizedViewEpoch, journalEpoch, sequence)`.
///
/// Step 2.2 defines the strict JSON schema and validation semantics only;
/// AEAD sealing of the envelope arrives with Steps 2.3/2.7.
public struct ReplayCursorEnvelope: Codable, Equatable, Sendable {
  public let deviceID: UUID
  public let grantRevision: UInt64
  public let authorizedViewEpoch: UInt64
  public let journalEpoch: JournalEpoch
  public let sequence: UInt64

  public init(
    deviceID: UUID,
    grantRevision: UInt64,
    authorizedViewEpoch: UInt64,
    journalEpoch: JournalEpoch,
    sequence: UInt64
  ) {
    self.deviceID = deviceID
    self.grantRevision = grantRevision
    self.authorizedViewEpoch = authorizedViewEpoch
    self.journalEpoch = journalEpoch
    self.sequence = sequence
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    self.init(
      deviceID: try container.decode(UUID.self, forKey: .deviceID),
      grantRevision: try container.decode(UInt64.self, forKey: .grantRevision),
      authorizedViewEpoch: try container.decode(UInt64.self, forKey: .authorizedViewEpoch),
      journalEpoch: try container.decode(JournalEpoch.self, forKey: .journalEpoch),
      sequence: try container.decode(UInt64.self, forKey: .sequence)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case deviceID
    case grantRevision
    case authorizedViewEpoch
    case journalEpoch
    case sequence
  }
}

/// The host's current authoritative values a presented cursor is validated
/// against. `oldestReplayableSequence` is the smallest cursor sequence the
/// journal can still replay after; anything older is retention-stale.
public struct ReplayCursorAuthority: Equatable, Sendable {
  public let deviceID: UUID
  public let grantRevision: UInt64
  public let authorizedViewEpoch: UInt64
  public let journalEpoch: JournalEpoch
  public let latestSequence: UInt64
  public let oldestReplayableSequence: UInt64

  public init(
    deviceID: UUID,
    grantRevision: UInt64,
    authorizedViewEpoch: UInt64,
    journalEpoch: JournalEpoch,
    latestSequence: UInt64,
    oldestReplayableSequence: UInt64
  ) throws {
    guard oldestReplayableSequence <= latestSequence else {
      throw SecureWireValidationError.invalidField(name: "oldestReplayableSequence")
    }
    self.deviceID = deviceID
    self.grantRevision = grantRevision
    self.authorizedViewEpoch = authorizedViewEpoch
    self.journalEpoch = journalEpoch
    self.latestSequence = latestSequence
    self.oldestReplayableSequence = oldestReplayableSequence
  }
}

/// Fail-closed cursor violations. "Ahead" revision/view values mean the
/// presented cursor claims authority state newer than the host currently
/// holds, which is rollback evidence and never downgraded to a snapshot.
public enum ReplayCursorViolation: Equatable, Sendable {
  case deviceMismatch
  case counterOverflow
  case grantRevisionAhead
  case authorizedViewEpochAhead
  case sequenceAhead
}

/// Snapshot-forcing causes. These are recoverable: the device receives a
/// fresh filtered snapshot instead of replay.
public enum ReplayCursorSnapshotCause: Equatable, Sendable {
  case staleGrantRevision
  case staleAuthorizedViewEpoch
  case foreignJournalEpoch
  case retentionExpired
}

/// Outcome of validating a presented cursor against current authority.
public enum ReplayCursorDecision: Equatable, Sendable {
  case replay(afterSequence: UInt64)
  case snapshot(ReplayCursorSnapshotCause)
  case reject(ReplayCursorViolation)
}

extension ReplayCursorEnvelope {
  /// Validates this cursor against the host's current authority.
  ///
  /// Precedence is fixed: device mismatch, counter overflow, and ahead
  /// revision/view fail closed first; then stale revision/view, foreign
  /// journal epoch, ahead sequence (fail closed), and retention staleness
  /// are evaluated; only a fully matching cursor may replay.
  public func evaluate(against authority: ReplayCursorAuthority) -> ReplayCursorDecision {
    guard deviceID == authority.deviceID else {
      return .reject(.deviceMismatch)
    }
    let counters = [
      grantRevision, authorizedViewEpoch, sequence,
      authority.grantRevision, authority.authorizedViewEpoch, authority.latestSequence,
    ]
    guard !counters.contains(UInt64.max) else {
      return .reject(.counterOverflow)
    }
    guard grantRevision <= authority.grantRevision else {
      return .reject(.grantRevisionAhead)
    }
    guard authorizedViewEpoch <= authority.authorizedViewEpoch else {
      return .reject(.authorizedViewEpochAhead)
    }
    guard grantRevision == authority.grantRevision else {
      return .snapshot(.staleGrantRevision)
    }
    guard authorizedViewEpoch == authority.authorizedViewEpoch else {
      return .snapshot(.staleAuthorizedViewEpoch)
    }
    guard journalEpoch == authority.journalEpoch else {
      return .snapshot(.foreignJournalEpoch)
    }
    guard sequence <= authority.latestSequence else {
      return .reject(.sequenceAhead)
    }
    guard sequence >= authority.oldestReplayableSequence else {
      return .snapshot(.retentionExpired)
    }
    return .replay(afterSequence: sequence)
  }
}
