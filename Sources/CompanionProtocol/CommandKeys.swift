import Foundation

/// The device's command keys and when each one is usable.
///
/// **Availability is derived, never discovered.** Phase 3 invariant 2 says a
/// control a device may not use is visibly unavailable rather than
/// present-and-failing, and the difference is not cosmetic: a key that looks
/// alive and refuses is indistinguishable from a key that looks alive and is
/// broken, so the user learns to distrust all of them. The hardware cannot
/// grey out a physical switch and has to teach you which keys do nothing;
/// software has no such excuse.
public enum CommandKey: String, CaseIterable, Sendable {
  /// Move the selection to the previous bound key.
  case previousAgent
  /// Move the selection to the next bound key.
  case nextAgent
  /// Interrupt the selected agent's running turn.
  case stop
  /// Mark the selected thread read.
  case markRead
  /// Steer the running turn with new input.
  case steer

  /// The capability this key spends, or `nil` when it is purely local.
  ///
  /// Navigation keys have no capability because they change what the phone is
  /// looking at and cause nothing to happen on the Mac. That distinction is
  /// worth keeping in the type: it is the reason those two keys stay usable
  /// on a device whose grant has been reduced to nothing.
  public var requiredCapability: DeviceCapability? {
    switch self {
    case .previousAgent, .nextAgent: return nil
    case .stop: return .interrupt
    case .markRead: return .view
    case .steer: return .runAgent
    }
  }

  /// Whether the key needs a selected agent to act on.
  public var requiresSelection: Bool {
    switch self {
    case .previousAgent, .nextAgent: return false
    case .stop, .markRead, .steer: return true
    }
  }

  /// Whether the key only makes sense while a turn is running.
  ///
  /// Stopping a finished agent and steering one that is not thinking are both
  /// no-ops that would return a refusal from the gateway. Showing them as
  /// unavailable is the same information, delivered before the tap instead of
  /// after it.
  public var requiresRunningTurn: Bool {
    switch self {
    case .stop, .steer: return true
    case .previousAgent, .nextAgent, .markRead: return false
    }
  }
}

/// Why a command key cannot be used, or that it can.
public enum CommandKeyAvailability: Equatable, Sendable {
  case available
  /// The grant does not include the capability this key spends.
  case notPermitted
  /// No agent key is selected.
  case noSelection
  /// The selected agent is not running a turn.
  case noRunningTurn
  /// There is no authenticated session, or the status is stale enough that
  /// acting on it would be acting on a guess.
  case notLive

  public var isAvailable: Bool { self == .available }
}

extension CommandKey {
  /// Resolves whether this key can be pressed right now.
  ///
  /// The order of the checks is the order the user would ask the questions in,
  /// and it matters for what the interface says: "you are not connected"
  /// outranks "you have not selected an agent", which outranks "your grant
  /// does not allow this", which outranks "that agent is not running". A
  /// disconnected device reporting a permission problem would send someone to
  /// change a grant that was never the issue.
  public func availability(
    in surface: DeviceSurfaceState,
    capabilities: Set<DeviceCapability>
  ) -> CommandKeyAvailability {
    guard surface.isConnected else { return .notLive }

    if requiresSelection {
      guard let key = surface.selectedKey, key.isBound else { return .noSelection }
      // A stale key's activity is a memory, not a fact. Acting on it would be
      // acting on a guess, which is the same lie invariant 1 forbids the key
      // from telling — arriving one step later.
      guard key.freshness == .live else { return .notLive }
      if requiresRunningTurn, key.activity != .working { return .noRunningTurn }
    }

    if let required = requiredCapability, !capabilities.contains(required) {
      return .notPermitted
    }
    return .available
  }
}
