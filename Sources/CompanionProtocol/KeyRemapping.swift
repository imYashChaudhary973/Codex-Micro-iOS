import Foundation

/// What a physical key position can be assigned to do.
///
/// The hardware ships 32 icon keycaps so the layout can match a workflow, and
/// every control is remappable. This is that, in software, where it is easier:
/// the cap and the binding cannot get out of sync because there is no cap.
public enum KeyAction: String, Codable, CaseIterable, Sendable {
  case previousAgent
  case nextAgent
  case stop
  case steer
  case markRead
  case pushToTalk
  case newChat
  case approve
  case decline
  /// Assigned to nothing. A key can be left blank, which is different from a
  /// key whose action the device may not perform.
  case none

  /// The capability this action spends, or `nil` when it is local to the phone.
  ///
  /// **This is the whole safety property of remapping.** A remap moves an
  /// action to a different position; it cannot change what the action costs.
  /// Because availability is resolved from this and from the grant — never
  /// from the position — moving `approve` onto the most convenient key does
  /// not make a device that lacks `.approve` able to use it.
  public var requiredCapability: DeviceCapability? {
    switch self {
    case .previousAgent, .nextAgent, .pushToTalk, .none: return nil
    case .stop: return .interrupt
    case .markRead: return .view
    case .steer: return .runAgent
    case .newChat: return .startThread
    case .approve, .decline: return .approve
    }
  }

  public var title: String {
    switch self {
    case .previousAgent: return "Prev"
    case .nextAgent: return "Next"
    case .stop: return "Stop"
    case .steer: return "Steer"
    case .markRead: return "Read"
    case .pushToTalk: return "Talk"
    case .newChat: return "New"
    case .approve: return "Approve"
    case .decline: return "Decline"
    case .none: return ""
    }
  }
}

/// The assignment of actions to the six command-key positions.
public struct KeyLayout: Equatable, Codable, Sendable {
  /// The device's command row holds six positions.
  public static let positionCount = 6

  public private(set) var actions: [KeyAction]

  /// What the pad does out of the box: the controls that need no capability
  /// beyond observing, plus the two that most workflows reach for.
  public static let `default` = KeyLayout(actions: [
    .previousAgent, .nextAgent, .stop, .steer, .markRead, .pushToTalk,
  ])

  public init(actions: [KeyAction]) {
    var normalised = Array(actions.prefix(Self.positionCount))
    normalised.append(
      contentsOf: Array(
        repeating: KeyAction.none, count: max(0, Self.positionCount - normalised.count)))
    self.actions = normalised
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    self.init(actions: try container.decode([KeyAction].self))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(actions)
  }

  public func action(at position: Int) -> KeyAction {
    guard actions.indices.contains(position) else { return .none }
    return actions[position]
  }

  /// Assigns an action to a position.
  ///
  /// The same action may sit in two positions. That is allowed on purpose: the
  /// hardware has no way to stop you putting two identical caps on, and a
  /// second stop key within thumb reach is a reasonable thing to want. What is
  /// not allowed is an action doing something different because of where it
  /// sits.
  public func assigning(_ action: KeyAction, to position: Int) -> KeyLayout {
    guard actions.indices.contains(position) else { return self }
    var next = actions
    next[position] = action
    return KeyLayout(actions: next)
  }

  /// The actions this layout uses that the device may not perform.
  ///
  /// Surfaced so the remapping screen can say "this key will not work" while
  /// the user is choosing, rather than leaving them to discover it later on a
  /// key they deliberately placed.
  public func unusableActions(given capabilities: Set<DeviceCapability>) -> Set<KeyAction> {
    Set(
      actions.filter { action in
        guard let required = action.requiredCapability else { return false }
        return !capabilities.contains(required)
      })
  }
}
