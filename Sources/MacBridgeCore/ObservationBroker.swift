import CompanionProtocol
import Foundation

/// Closed observation-subscription failure vocabulary. Carries no content.
public enum ObservationSubscriptionError: Error, Equatable, Sendable {
  /// The device holds no live grant with `.view`, so it may not observe.
  /// Unknown, revoked, expired, and capability-less devices are one
  /// outcome here; the specific closed reason belongs to the session layer,
  /// which already knows the device's liveness.
  case notObservable
  /// The grant authority could not be read. Authorization cannot be
  /// confirmed, so nothing is disclosed (plan §2 invariant 15).
  case authorityUnavailable
  /// A presented cursor failed closed rather than resynchronizing: wrong
  /// device, a counter ahead of authority, or an overflowed value. The
  /// transport must close the connection.
  case cursorRejected(ReplayCursorViolation)
  /// The acknowledgement names a subscription this device does not hold.
  case unknownSubscription
  /// The acknowledged sequence moved backwards, or claimed data that was
  /// never delivered.
  case acknowledgementOutOfOrder
  /// Projection failed closed; see ``ObservationProjectionError``.
  case projectionFailed(ObservationProjectionError)
}

/// Fixed observation-subscription ceilings.
public enum ObservationLimits {
  /// Maximum events delivered but not yet acknowledged on one subscription.
  ///
  /// This is the bounded queue: once the device is this far behind, no
  /// further event batch is produced until it acknowledges. It bounds
  /// outbound work per device independently of the transport's own
  /// per-connection frame and byte ceilings (ADR §9).
  public static let maxUnacknowledgedEvents: UInt64 = 128
  /// Maximum events in one produced batch. Matches the wire bound.
  public static let maxEventsPerBatch = SecureObservationLimits.maxEventBatchCount
}

/// Whether a device may currently observe, and under which scope.
public enum ObservationScopeResult: Equatable, Sendable {
  case scoped(AuthorizedViewScope)
  /// No live grant, or a live grant without `.view`.
  case notObservable
}

/// Reads the Mac-authoritative disclosure scope for one device.
///
/// Throwing means the authority itself is unavailable, which denies
/// disclosure outright — there is no cached scope and no memory-only
/// fallback (plan §2 invariant 15).
public protocol ObservationScopeProviding: Sendable {
  func observationScope(deviceID: UUID) async throws -> ObservationScopeResult
}

/// Supplies the current unfiltered bridge snapshot.
///
/// Only the broker calls this, and only to filter the result immediately;
/// no unfiltered snapshot ever leaves ``DeviceObservationBroker`` (plan §9
/// ownership: `MacBridgeServer` never receives an unfiltered journal).
public protocol ObservationSnapshotProviding: Sendable {
  func currentObservationSnapshot() async -> CompanionStateSnapshot
}

/// What applying a committed authorization change discarded for one device.
public struct ObservationPurgeResult: Equatable, Sendable {
  /// Whether the device held a subscription when the change was applied.
  public let hadSubscription: Bool
  /// Retained authorized events the change dropped.
  public let discardedEvents: Int
  /// Whether the device may still observe after the change.
  public let retainsObservation: Bool
}

/// One device's subscription watermarks.
public struct ObservationSubscription: Equatable, Sendable {
  public let subscriptionID: UUID
  public let deviceID: UUID
  /// The authorized-view epoch these watermarks belong to. When the device's
  /// committed view epoch moves, the sequence namespace they name no longer
  /// exists, so they are reset and a fresh filtered snapshot is forced.
  public internal(set) var authorizedViewEpoch: UInt64
  /// Highest sequence the device acknowledged. It is the replay floor a
  /// reconnect resumes from, so retention is measured against it.
  public internal(set) var acknowledgedSequence: UInt64
  /// Highest sequence handed to the transport. Never below
  /// ``acknowledgedSequence``.
  public internal(set) var deliveredSequence: UInt64
  /// Set when the next delivery must be a fresh filtered snapshot.
  public internal(set) var needsSnapshot: Bool
}

/// The Mac-side owner of authenticated `observe` sessions' data flow.
///
/// It holds one ``DeviceAuthorizedView`` per device and one subscription per
/// device, and hands the transport nothing but already-filtered
/// ``AuthorizedObservationBatch`` values.
///
/// **Scope is re-read on every operation.** The broker caches no
/// authorization decision across calls, so an authorization change that has
/// already committed in the grant authority is in force for the very next
/// subscribe, poll, or acknowledgement — which is what makes
/// commit-then-purge-then-close linearizable rather than racy (plan §2
/// invariant 11).
///
/// **Back-pressure, not gaps.** A device that stops acknowledging stops
/// receiving event batches once ``ObservationLimits/maxUnacknowledgedEvents``
/// are outstanding. If it falls so far behind that the retention ring no
/// longer covers everything after its acknowledged sequence, the next
/// delivery is a fresh filtered snapshot — the slow-consumer fallback ADR §9
/// allows above the transport's own close policy. A partial history is never
/// sent.
public actor DeviceObservationBroker {
  private let scopes: any ObservationScopeProviding
  private let snapshots: any ObservationSnapshotProviding
  private let attribution: any ThreadProjectAttributing
  private let journalEpoch: JournalEpoch
  private let retainedEventCapacity: Int
  private var views: [UUID: DeviceAuthorizedView] = [:]
  private var subscriptions: [UUID: ObservationSubscription] = [:]

  /// - Parameters:
  ///   - journalEpoch: The epoch minted for this bridge process. A cursor
  ///     carrying any other epoch is foreign and resynchronizes by snapshot.
  public init(
    scopes: any ObservationScopeProviding,
    snapshots: any ObservationSnapshotProviding,
    attribution: any ThreadProjectAttributing,
    journalEpoch: JournalEpoch,
    retainedEventCapacity: Int = DeviceAuthorizedView.defaultRetainedEventCapacity
  ) {
    self.scopes = scopes
    self.snapshots = snapshots
    self.attribution = attribution
    self.journalEpoch = journalEpoch
    self.retainedEventCapacity = retainedEventCapacity
  }

  /// The epoch every cursor this broker issues carries.
  public nonisolated var currentJournalEpoch: JournalEpoch { journalEpoch }

  // MARK: - Domain changes

  /// Projects one bridge domain change onto every device that may see it.
  ///
  /// Returns the devices whose view advanced, so the transport can wake
  /// exactly those connections. A device that may not see the change is not
  /// in the result and its sequence did not move.
  ///
  /// Devices are projected independently: a projection failure on one device
  /// (a fixed-width sequence, an out-of-bound identifier) disables that
  /// device's view for the change without affecting any other.
  @discardableResult
  ///
  /// `thread` is the change's resulting state. Callers that have it should
  /// pass it: the event carries it to the device, which is what keeps six
  /// status keys correct between snapshots. Callers that do not have it pass
  /// nothing and the device learns only that something moved.
  public func recordThreadChange(
    threadID: String,
    thread: ObservedThreadState? = nil
  ) async -> [UUID] {
    let projectID = attribution.projectID(forThreadID: threadID)
    var advanced: [UUID] = []
    for deviceID in subscriptions.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
      guard let scope = try? await refreshedScope(deviceID: deviceID) else { continue }
      guard var view = views[deviceID] else { continue }
      view.adopt(scope: scope)
      let event = try? view.admit(
        threadID: threadID, projectID: projectID, thread: thread)
      views[deviceID] = view
      if event != nil {
        advanced.append(deviceID)
      }
    }
    return advanced
  }

  // MARK: - Subscription lifecycle

  /// Opens or replaces the device's subscription and returns its first
  /// batch.
  ///
  /// `deviceID` must come from session authentication, never from the
  /// message; a resume cursor naming any other device fails closed.
  public func subscribe(
    deviceID: UUID,
    subscriptionID: UUID,
    resumeCursor: ReplayCursorEnvelope?
  ) async throws -> AuthorizedObservationBatch {
    let view = try await synchronizedView(deviceID: deviceID)

    var subscription = ObservationSubscription(
      subscriptionID: subscriptionID,
      deviceID: deviceID,
      authorizedViewEpoch: view.scope.authorizedViewEpoch,
      acknowledgedSequence: view.latestSequence,
      deliveredSequence: view.latestSequence,
      needsSnapshot: true
    )
    if let resumeCursor {
      switch resumeCursor.evaluate(against: try cursorAuthority(view)) {
      case .replay(let afterSequence):
        subscription.acknowledgedSequence = afterSequence
        subscription.deliveredSequence = afterSequence
        subscription.needsSnapshot = false
      case .snapshot:
        break
      case .reject(let violation):
        throw ObservationSubscriptionError.cursorRejected(violation)
      }
    }
    subscriptions[deviceID] = subscription
    guard
      let batch = try await buildBatch(
        deviceID: deviceID, view: view, snapshotWhenCaughtUp: true)
    else {
      throw ObservationSubscriptionError.unknownSubscription
    }
    return batch
  }

  /// The next batch for a device, or `nil` when it is fully caught up or
  /// back-pressured.
  public func nextBatch(deviceID: UUID) async throws -> AuthorizedObservationBatch? {
    let view = try await synchronizedView(deviceID: deviceID)
    guard subscriptions[deviceID] != nil else {
      throw ObservationSubscriptionError.unknownSubscription
    }
    return try await buildBatch(deviceID: deviceID, view: view, snapshotWhenCaughtUp: false)
  }

  /// Records the device's acknowledgement of delivered data.
  ///
  /// A cursor that resynchronizes (stale revision or view epoch, foreign
  /// epoch, retention-stale) does not advance the watermark; it schedules a
  /// fresh filtered snapshot. A cursor that fails closed throws.
  public func acknowledge(
    deviceID: UUID,
    subscriptionID: UUID,
    cursor: ReplayCursorEnvelope
  ) async throws {
    let view = try await synchronizedView(deviceID: deviceID)
    guard var subscription = subscriptions[deviceID],
      subscription.subscriptionID == subscriptionID
    else {
      throw ObservationSubscriptionError.unknownSubscription
    }

    switch cursor.evaluate(against: try cursorAuthority(view)) {
    case .replay(let afterSequence):
      guard afterSequence >= subscription.acknowledgedSequence,
        afterSequence <= subscription.deliveredSequence
      else {
        throw ObservationSubscriptionError.acknowledgementOutOfOrder
      }
      subscription.acknowledgedSequence = afterSequence
    case .snapshot:
      subscription.needsSnapshot = true
    case .reject(let violation):
      throw ObservationSubscriptionError.cursorRejected(violation)
    }
    subscriptions[deviceID] = subscription
  }

  /// Drops the device's subscription. The retained view survives so a
  /// reconnect inside retention can still replay.
  public func unsubscribe(deviceID: UUID) {
    subscriptions.removeValue(forKey: deviceID)
  }

  /// Discards every trace of a device: its subscription and its retained
  /// authorized history. Called by the authorization-change path after the
  /// authority commit, so no queued or retained data outlives the grant that
  /// authorized it (plan §2 invariant 11).
  public func purge(deviceID: UUID) {
    subscriptions.removeValue(forKey: deviceID)
    views.removeValue(forKey: deviceID)
  }

  /// Applies an authorization change that has **already committed** in the
  /// grant authority, and reports what the purge discarded.
  ///
  /// The authorization-change path calls this between the authority commit
  /// and closing the device's connections, so no queued or retained data
  /// survives the grant that authorized it even for the moment it takes the
  /// transport to close (plan §2 invariant 11). It never reads the authority
  /// twice for one decision: whatever the authority now says is what takes
  /// effect.
  @discardableResult
  public func applyCommittedAuthorization(deviceID: UUID) async -> ObservationPurgeResult {
    let hadSubscription = subscriptions[deviceID] != nil
    let retainedBefore = views[deviceID]?.events(after: 0).count ?? 0
    do {
      let view = try await synchronizedView(deviceID: deviceID)
      return ObservationPurgeResult(
        hadSubscription: hadSubscription,
        discardedEvents: max(0, retainedBefore - view.events(after: 0).count),
        retainsObservation: true
      )
    } catch {
      // `synchronizedView` already purged the device on the denial path; an
      // unavailable authority is equally a reason to disclose nothing.
      purge(deviceID: deviceID)
      return ObservationPurgeResult(
        hadSubscription: hadSubscription,
        discardedEvents: retainedBefore,
        retainsObservation: false
      )
    }
  }

  /// Test and diagnostic read of a device's subscription watermarks.
  /// How many devices currently hold a subscription.
  ///
  /// A count and nothing else: it says whether anyone is watching without
  /// naming who, which is the same content-free shape the menu metrics use.
  public func observingDeviceCount() -> Int { subscriptions.count }

  public func subscription(deviceID: UUID) -> ObservationSubscription? {
    subscriptions[deviceID]
  }

  /// Test and diagnostic read of a device's projected view.
  public func view(deviceID: UUID) -> DeviceAuthorizedView? {
    views[deviceID]
  }

  // MARK: - Batch production

  private func buildBatch(
    deviceID: UUID,
    view: DeviceAuthorizedView,
    snapshotWhenCaughtUp: Bool
  ) async throws -> AuthorizedObservationBatch? {
    guard var subscription = subscriptions[deviceID] else {
      throw ObservationSubscriptionError.unknownSubscription
    }

    // The retention ring no longer covers everything the device still needs:
    // resynchronize by snapshot rather than sending a partial history.
    if subscription.acknowledgedSequence < view.oldestReplayableSequence {
      subscription.needsSnapshot = true
    }

    if subscription.needsSnapshot {
      let batch = try await snapshotBatch(view: view)
      subscription.needsSnapshot = false
      subscription.deliveredSequence = view.latestSequence
      subscription.acknowledgedSequence = min(
        subscription.acknowledgedSequence, view.latestSequence)
      subscriptions[deviceID] = subscription
      return batch
    }

    let outstanding = subscription.deliveredSequence - subscription.acknowledgedSequence
    guard outstanding < ObservationLimits.maxUnacknowledgedEvents else {
      subscriptions[deviceID] = subscription
      return snapshotWhenCaughtUp ? try await snapshotBatch(view: view) : nil
    }

    let budget = Int(ObservationLimits.maxUnacknowledgedEvents - outstanding)
    let pending = view.events(after: subscription.deliveredSequence)
      .prefix(min(budget, ObservationLimits.maxEventsPerBatch))
    guard let last = pending.last else {
      subscriptions[deviceID] = subscription
      return snapshotWhenCaughtUp ? try await snapshotBatch(view: view) : nil
    }

    guard let payload = try? SecureObservationEventBatch(events: Array(pending)) else {
      throw ObservationSubscriptionError.projectionFailed(.projectionOversized)
    }
    subscription.deliveredSequence = last.sequence
    subscriptions[deviceID] = subscription
    return .events(payload, cursor: view.cursor(at: last.sequence, journalEpoch: journalEpoch))
  }

  private func snapshotBatch(
    view: DeviceAuthorizedView
  ) async throws -> AuthorizedObservationBatch {
    let unfiltered = await snapshots.currentObservationSnapshot()
    do {
      let filtered = try AuthorizedSnapshotProjection.filter(
        unfiltered, scope: view.scope, attribution: attribution)
      return .snapshot(
        filtered, cursor: view.cursor(at: view.latestSequence, journalEpoch: journalEpoch))
    } catch let error as ObservationProjectionError {
      throw ObservationSubscriptionError.projectionFailed(error)
    }
  }

  // MARK: - Scope

  /// Re-reads the committed scope, adopts it into the device's view, and
  /// reconciles the subscription with it.
  ///
  /// This is the single point where an authorization change takes effect, and
  /// it runs before every disclosure decision. A view epoch that moved means
  /// the sequence namespace the watermarks named no longer exists, so they
  /// reset and the next delivery is a fresh filtered snapshot (plan §2
  /// invariants 5 and 11). A device that is no longer observable loses its
  /// subscription and its retained history here.
  private func synchronizedView(deviceID: UUID) async throws -> DeviceAuthorizedView {
    guard let scope = try await refreshedScope(deviceID: deviceID) else {
      purge(deviceID: deviceID)
      throw ObservationSubscriptionError.notObservable
    }
    var view =
      views[deviceID]
      ?? DeviceAuthorizedView(scope: scope, retainedEventCapacity: retainedEventCapacity)
    view.adopt(scope: scope)
    views[deviceID] = view

    if var subscription = subscriptions[deviceID],
      subscription.authorizedViewEpoch != scope.authorizedViewEpoch
    {
      subscription.authorizedViewEpoch = scope.authorizedViewEpoch
      subscription.acknowledgedSequence = view.latestSequence
      subscription.deliveredSequence = view.latestSequence
      subscription.needsSnapshot = true
      subscriptions[deviceID] = subscription
    }
    return view
  }

  private func refreshedScope(deviceID: UUID) async throws -> AuthorizedViewScope? {
    let result: ObservationScopeResult
    do {
      result = try await scopes.observationScope(deviceID: deviceID)
    } catch {
      throw ObservationSubscriptionError.authorityUnavailable
    }
    switch result {
    case .scoped(let scope): return scope
    case .notObservable: return nil
    }
  }

  private func cursorAuthority(_ view: DeviceAuthorizedView) throws -> ReplayCursorAuthority {
    do {
      return try view.cursorAuthority(journalEpoch: journalEpoch)
    } catch {
      throw ObservationSubscriptionError.projectionFailed(.projectionOversized)
    }
  }
}
