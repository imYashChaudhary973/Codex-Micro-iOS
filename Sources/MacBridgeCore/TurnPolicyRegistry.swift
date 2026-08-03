import Foundation

/// What the Mac recorded about one turn it started on a device's behalf.
///
/// This is the **authoritative state** steering is proven against. A turn the
/// bridge did not start — one begun in the IDE, or one from a previous
/// bridge process — has no record, and a turn with no record can never be
/// steered from a phone.
public struct RecordedTurnPolicy: Equatable, Sendable {
  public let threadID: String
  public let turnID: String
  /// The effective mobile action profile the turn actually runs under, after
  /// the gateway intersected the device grant's ceiling with the host
  /// profile.
  public let effectiveProfile: MobileActionProfile
  /// The exact bridge-resolved settings the turn was started with.
  public let policy: PhoneTurnPolicy
  /// The device whose command started the turn. Recorded for administration
  /// and diagnostics; steering authority is decided by the profile
  /// comparison, not by ownership.
  public let startedByDeviceID: UUID

  public init(
    threadID: String,
    turnID: String,
    effectiveProfile: MobileActionProfile,
    policy: PhoneTurnPolicy,
    startedByDeviceID: UUID
  ) {
    self.threadID = threadID
    self.turnID = turnID
    self.effectiveProfile = effectiveProfile
    self.policy = policy
    self.startedByDeviceID = startedByDeviceID
  }
}

/// Why a steer request was refused.
public enum TurnSteeringRefusal: Error, Equatable, Sendable {
  /// No authoritative record exists for the turn, so its effective policy
  /// cannot be proven. A turn started outside this bridge process — in the
  /// IDE, or before a restart — always lands here.
  case policyUnknown
  /// The turn is running under a broader policy than the device's current
  /// effective profile permits.
  case policyBroaderThanDevice
}

/// Records the effective policy of every turn the bridge starts, so steering
/// can be proven rather than assumed (plan Step 2.11).
///
/// **Memory-only by design.** A bridge restart loses every record, and a lost
/// record means steering is refused as `policyUnknown` — the safe direction.
/// Persisting it would make a stale record outlive the runtime that could
/// honour it, which is worse: the phone would be told a turn is steerable
/// under a policy no live turn is actually running.
///
/// The registry is bounded. Turns accumulate over a long-lived bridge, so it
/// keeps the most recent ``capacity`` records and evicts the oldest; an
/// evicted turn becomes unprovable and is refused, never assumed.
public actor TurnPolicyRegistry {
  /// Maximum turns tracked at once.
  public static let defaultCapacity = 512

  private struct Key: Hashable {
    let threadID: String
    let turnID: String
  }

  private let capacity: Int
  private var records: [Key: RecordedTurnPolicy] = [:]
  private var order: [Key] = []

  public init(capacity: Int = defaultCapacity) {
    self.capacity = max(1, capacity)
  }

  /// Records a turn the bridge just started, replacing any prior record for
  /// the same `(threadID, turnID)`.
  public func record(_ recorded: RecordedTurnPolicy) {
    let key = Key(threadID: recorded.threadID, turnID: recorded.turnID)
    if records[key] == nil {
      order.append(key)
    }
    records[key] = recorded
    while order.count > capacity, let oldest = order.first {
      order.removeFirst()
      records.removeValue(forKey: oldest)
    }
  }

  /// The recorded policy for a turn, or `nil` when the bridge cannot prove
  /// one.
  public func policy(threadID: String, turnID: String) -> RecordedTurnPolicy? {
    records[Key(threadID: threadID, turnID: turnID)]
  }

  /// Decides whether a device may steer a turn.
  ///
  /// Two refusals, in this order: a turn the bridge cannot prove anything
  /// about, and a turn running under a policy broader than the device's
  /// current effective profile. Equal or narrower policies are steerable.
  public func authorizeSteering(
    threadID: String,
    turnID: String,
    deviceEffectiveProfile: MobileActionProfile
  ) -> Result<RecordedTurnPolicy, TurnSteeringRefusal> {
    guard let recorded = policy(threadID: threadID, turnID: turnID) else {
      return .failure(.policyUnknown)
    }
    guard
      MobileActionProfile.mostRestrictive([
        recorded.effectiveProfile, deviceEffectiveProfile,
      ]) == recorded.effectiveProfile
    else {
      return .failure(.policyBroaderThanDevice)
    }
    return .success(recorded)
  }

  /// How many turns are currently tracked.
  public var trackedTurnCount: Int { records.count }
}
