import CompanionProtocol
import Foundation

/// One device's current disclosure scope, derived from the Mac-authoritative
/// grant record.
///
/// The scope is the whole authorization input to projection: nothing a phone
/// presents contributes to it (plan §2 invariant 1). Observation additionally
/// requires the `.view` capability, so pairing's default grant — `observe`
/// with an empty project allowlist — discloses no project at all until the
/// Mac user selects one (plan §2 invariant 4).
public struct AuthorizedViewScope: Equatable, Sendable {
  public let deviceID: UUID
  public let grantRevision: UInt64
  public let authorizedViewEpoch: UInt64
  public let permittedProjectIDs: Set<String>
  /// Whether this device may observe at all. False for a tombstoned grant
  /// or one without `.view`, and then the permitted set is empty regardless
  /// of what the record stores.
  public let allowsObservation: Bool
  /// What the device may do, told to it so its controls can show as
  /// unavailable rather than failing when pressed (Phase 3 invariant 2).
  ///
  /// Empty for a device that may not observe, on the same fail-closed
  /// reasoning as ``permittedProjectIDs``: a tombstoned grant reports no
  /// capabilities regardless of what the record still stores, so a revoked
  /// device is told it may do nothing rather than being told what it used to
  /// be allowed.
  public let capabilities: Set<DeviceCapability>
  /// Reasoning-effort values this host offers, in the model's advertised
  /// order. Empty when the host offers none, which the dial shows as having
  /// nothing to choose between rather than inventing positions.
  public let reasoningEfforts: [String]

  /// Derives the scope from the authoritative record.
  public init(grant: AuthoritativeDeviceGrant) {
    let allowsObservation = grant.tombstone == nil && grant.capabilities.contains(.view)
    self.deviceID = grant.deviceID
    self.grantRevision = grant.grantRevision
    self.authorizedViewEpoch = grant.authorizedViewEpoch
    self.allowsObservation = allowsObservation
    self.permittedProjectIDs = allowsObservation ? grant.permittedProjectIDs : []
    self.capabilities = allowsObservation ? grant.capabilities : []
    self.reasoningEfforts = []
  }

  /// Adds the host's advertised reasoning efforts to a scope.
  ///
  /// Separate from the grant because the efforts are a property of the model
  /// the host is running, not of the device's authorization. A revoked device
  /// still reports none, because its capabilities are empty and the dial is
  /// unavailable on that basis alone.
  public func offering(reasoningEfforts efforts: [String]) -> AuthorizedViewScope {
    AuthorizedViewScope(
      deviceID: deviceID,
      grantRevision: grantRevision,
      authorizedViewEpoch: authorizedViewEpoch,
      permittedProjectIDs: permittedProjectIDs,
      allowsObservation: allowsObservation,
      capabilities: capabilities,
      reasoningEfforts: allowsObservation ? efforts : []
    )
  }

  init(
    deviceID: UUID,
    grantRevision: UInt64,
    authorizedViewEpoch: UInt64,
    permittedProjectIDs: Set<String>,
    allowsObservation: Bool,
    capabilities: Set<DeviceCapability>,
    reasoningEfforts: [String]
  ) {
    self.deviceID = deviceID
    self.grantRevision = grantRevision
    self.authorizedViewEpoch = authorizedViewEpoch
    self.permittedProjectIDs = permittedProjectIDs
    self.allowsObservation = allowsObservation
    self.capabilities = capabilities
    self.reasoningEfforts = reasoningEfforts
  }

  /// Whether a resolved project is inside this device's current view. An
  /// unattributed thread (`nil`) is never permitted.
  public func permits(projectID: String?) -> Bool {
    guard allowsObservation, let projectID else { return false }
    return permittedProjectIDs.contains(projectID)
  }
}

/// One already-authorized batch, ready for a transport to seal and send.
///
/// `MacBridgeServer` receives only values of this type: every element inside
/// has already been filtered against the current Mac-stored scope, and the
/// cursor carries the device's own authorized-view sequence, never the
/// host's journal sequence (plan §9 ownership).
public enum AuthorizedObservationBatch: Equatable, Sendable {
  case snapshot(SecureObservationSnapshot, cursor: ReplayCursorEnvelope)
  case events(SecureObservationEventBatch, cursor: ReplayCursorEnvelope)

  public var cursor: ReplayCursorEnvelope {
    switch self {
    case .snapshot(_, let cursor), .events(_, let cursor): cursor
    }
  }
}

/// One device's private projection of bridge activity.
///
/// **The sequence namespace is per device.** A change the device may not see
/// is not merely filtered out of delivery — it never receives a sequence
/// value at all, so the numbers the device observes stay contiguous and
/// reveal nothing about how much unauthorized activity occurred (plan §2
/// invariant 5). This is why the projection cannot be a filter over the
/// shared journal's sequence values.
///
/// Retained events are bounded. A cursor older than what remains is
/// retention-stale and receives a fresh filtered snapshot rather than a
/// partial history, which is also the slow-consumer fallback: a subscription
/// whose watermark falls out of the ring is resynchronized by snapshot
/// instead of closing the connection.
public struct DeviceAuthorizedView: Equatable, Sendable {
  /// Retained events per device. Bounded so an idle or absent device cannot
  /// grow memory without limit; overflow degrades to a snapshot, never to a
  /// gap.
  public static let defaultRetainedEventCapacity = 512

  public private(set) var scope: AuthorizedViewScope
  /// The highest sequence assigned to this device. `0` means nothing
  /// visible has happened in the current authorized-view epoch.
  public private(set) var latestSequence: UInt64
  private var retained: [SecureObservationEvent]
  private let capacity: Int

  /// Creates a view at the start of a fresh authorized-view epoch.
  public init(scope: AuthorizedViewScope, retainedEventCapacity: Int = defaultRetainedEventCapacity)
  {
    self.scope = scope
    self.latestSequence = 0
    self.retained = []
    self.capacity = max(1, retainedEventCapacity)
  }

  /// Internal seam letting deterministic tests start a view near the
  /// fixed-width boundary, so overflow is provable without admitting
  /// `UInt64.max` events. Production code always starts at zero.
  init(
    scope: AuthorizedViewScope,
    latestSequence: UInt64,
    retainedEventCapacity: Int = defaultRetainedEventCapacity
  ) {
    self.scope = scope
    self.latestSequence = latestSequence
    self.retained = []
    self.capacity = max(1, retainedEventCapacity)
  }

  /// The smallest cursor sequence this view can still replay after.
  ///
  /// With no retained events only the current watermark replays, and it
  /// yields nothing.
  public var oldestReplayableSequence: UInt64 {
    guard let first = retained.first else { return latestSequence }
    return first.sequence - 1
  }

  /// Records a domain change against this device's view.
  ///
  /// Returns the assigned event when the change is visible, and `nil` when
  /// it is not — in which case **no sequence is consumed**. `projectID` is
  /// the attribution result; `nil` means unattributable, which is never
  /// visible.
  public mutating func admit(
    threadID: String,
    projectID: String?
  ) throws -> SecureObservationEvent? {
    guard scope.permits(projectID: projectID), let projectID else { return nil }
    guard latestSequence < UInt64.max - 1 else {
      throw ObservationProjectionError.sequenceExhausted
    }
    guard
      let event = try? SecureObservationEvent(
        sequence: latestSequence + 1,
        kind: .threadUpdated,
        threadID: threadID,
        projectID: projectID
      )
    else {
      throw ObservationProjectionError.projectionOversized
    }
    latestSequence = event.sequence
    retained.append(event)
    if retained.count > capacity {
      retained.removeFirst(retained.count - capacity)
    }
    return event
  }

  /// Retained authorized events strictly after `sequence`.
  public func events(after sequence: UInt64) -> [SecureObservationEvent] {
    retained.filter { $0.sequence > sequence }
  }

  /// The authority a presented cursor is validated against.
  public func cursorAuthority(journalEpoch: JournalEpoch) throws -> ReplayCursorAuthority {
    try ReplayCursorAuthority(
      deviceID: scope.deviceID,
      grantRevision: scope.grantRevision,
      authorizedViewEpoch: scope.authorizedViewEpoch,
      journalEpoch: journalEpoch,
      latestSequence: latestSequence,
      oldestReplayableSequence: oldestReplayableSequence
    )
  }

  /// Issues a cursor at `sequence` in this view's current namespace.
  public func cursor(at sequence: UInt64, journalEpoch: JournalEpoch) -> ReplayCursorEnvelope {
    ReplayCursorEnvelope(
      deviceID: scope.deviceID,
      grantRevision: scope.grantRevision,
      authorizedViewEpoch: scope.authorizedViewEpoch,
      journalEpoch: journalEpoch,
      sequence: sequence
    )
  }

  /// Adopts a newly committed scope for the same device.
  ///
  /// A changed authorized-view epoch means the disclosure boundary moved, so
  /// the retained history is purged and the sequence namespace restarts —
  /// no value assigned under the previous boundary survives (plan §2
  /// invariant 11). A revision-only change leaves history intact because the
  /// boundary did not move; a presented cursor still resynchronizes by
  /// snapshot, because its stale revision forces one.
  public mutating func adopt(scope: AuthorizedViewScope) {
    guard scope.deviceID == self.scope.deviceID else { return }
    let boundaryMoved = scope.authorizedViewEpoch != self.scope.authorizedViewEpoch
    self.scope = scope
    if boundaryMoved {
      retained = []
      latestSequence = 0
    }
  }
}

/// Builds the filtered snapshot payload for one device.
public enum AuthorizedSnapshotProjection {
  /// Projects a bridge snapshot down to what one device may see.
  ///
  /// Threads outside the device's project scope and threads with no
  /// attribution are absent — not redacted, not counted, not represented.
  /// Approvals are excluded from the observation surface entirely (Phase 2
  /// negotiates no approval feature).
  ///
  /// Exceeding the wire's thread bound fails closed with
  /// ``ObservationProjectionError/projectionOversized`` rather than
  /// truncating, because a silently short snapshot is indistinguishable from
  /// a complete one.
  public static func filter(
    _ snapshot: CompanionStateSnapshot,
    scope: AuthorizedViewScope,
    attribution: some ThreadProjectAttributing
  ) throws -> SecureObservationSnapshot {
    var observed: [ObservedThreadState] = []
    for thread in snapshot.threads {
      let projectID = attribution.projectID(forThreadID: thread.threadID)
      guard scope.permits(projectID: projectID), let projectID else { continue }
      guard
        let state = try? ObservedThreadState(
          threadID: thread.threadID,
          projectID: projectID,
          status: thread.status,
          activeTurnID: thread.activeTurnID,
          lastTurnID: thread.lastTurnID,
          lastTurnStatus: thread.lastTurnStatus
        )
      else {
        throw ObservationProjectionError.projectionOversized
      }
      observed.append(state)
    }
    observed.sort { $0.threadID < $1.threadID }
    guard
      let filtered = try? SecureObservationSnapshot(
        generatedAtEpochSeconds: UInt64(max(0, snapshot.generatedAt.timeIntervalSince1970)),
        threads: observed,
        capabilities: scope.capabilities,
        reasoningEfforts: scope.reasoningEfforts
      )
    else {
      throw ObservationProjectionError.projectionOversized
    }
    return filtered
  }
}
