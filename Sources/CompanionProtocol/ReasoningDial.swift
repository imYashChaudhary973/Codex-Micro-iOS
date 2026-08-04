import Foundation

/// The reasoning dial's state.
///
/// **When a change takes effect is part of the reading, not a footnote.**
/// The hardware's dial is described as turnable mid-task to raise reasoning
/// for a hard problem. The app-server surface does not work that way:
/// `TurnStartParams.effort` overrides "for this turn and subsequent turns" and
/// `TurnSteerParams` has no effort field at all, so a change made while a turn
/// is running lands on the *next* turn.
///
/// That is a real divergence from the device and the dial states it rather
/// than hiding it. A control that silently defers its effect is worse than one
/// that says it will: the user turns it, sees nothing change, and concludes
/// the control is broken.
public struct ReasoningDialState: Equatable, Sendable {
  /// Available positions, in the model's own advertised order.
  public let positions: [String]
  /// The position the device has selected, if any.
  public let selected: String?
  /// Whether the selection will apply now or to the next turn.
  public let timing: Timing
  /// Why the dial cannot be used, or `nil` when it can.
  public let unavailability: Unavailability?

  public enum Timing: Equatable, Sendable {
    /// No turn is running; the next turn started from here uses this setting.
    case nextTurn
    /// A turn is running and will not change. The setting applies afterwards.
    case afterCurrentTurn
  }

  public enum Unavailability: String, Equatable, Sendable {
    /// The host advertised no efforts, so there is nothing to choose between.
    case noPositionsOffered
    /// The device may not start or steer agent work at all.
    case notPermitted
    /// No agent is selected, so there is nothing to configure.
    case noSelection
    /// Not connected, or the status is too stale to act on.
    case notLive
  }

  public var isAvailable: Bool { unavailability == nil }

  public init(
    positions: [String],
    selected: String?,
    timing: Timing,
    unavailability: Unavailability?
  ) {
    self.positions = positions
    self.selected = selected
    self.timing = timing
    self.unavailability = unavailability
  }

  /// Resolves the dial for the current surface.
  ///
  /// - Parameter requested: What the device last asked for. Kept only if the
  ///   host still advertises it: a host that changed models mid-session may no
  ///   longer offer the level the dial is pointing at, and continuing to show
  ///   it would be the dial claiming a setting that would be dropped on send.
  public static func resolve(
    positions: [String],
    requested: String?,
    surface: DeviceSurfaceState,
    capabilities: Set<DeviceCapability>
  ) -> ReasoningDialState {
    let selected = requested.flatMap { positions.contains($0) ? $0 : nil }
    let timing: Timing =
      surface.selectedKey?.activity == .working ? .afterCurrentTurn : .nextTurn

    let unavailability: Unavailability?
    if !surface.isConnected {
      unavailability = .notLive
    } else if surface.selectedKey?.isBound != true {
      unavailability = .noSelection
    } else if surface.selectedKey?.freshness != .live {
      unavailability = .notLive
    } else if !capabilities.contains(.runAgent) {
      // The dial only affects turns this device could start or steer. Offering
      // it to a device that can do neither would be a control with no effect.
      unavailability = .notPermitted
    } else if positions.isEmpty {
      unavailability = .noPositionsOffered
    } else {
      unavailability = nil
    }

    return ReasoningDialState(
      positions: positions,
      selected: selected,
      timing: timing,
      unavailability: unavailability
    )
  }

  /// The position one detent away, or `nil` at the end of travel.
  ///
  /// A real dial stops rather than wrapping. Wrapping from the highest setting
  /// straight to the lowest is the kind of surprise that costs a long turn.
  public func stepped(by delta: Int) -> String? {
    guard !positions.isEmpty else { return nil }
    guard let selected, let index = positions.firstIndex(of: selected) else {
      return delta >= 0 ? positions.first : positions.last
    }
    let next = index + delta
    guard positions.indices.contains(next) else { return nil }
    return positions[next]
  }

  /// What the dial says about when its setting applies.
  public var timingDescription: String {
    switch timing {
    case .nextTurn: return "Applies to the next turn"
    case .afterCurrentTurn: return "Applies after the running turn"
    }
  }
}
