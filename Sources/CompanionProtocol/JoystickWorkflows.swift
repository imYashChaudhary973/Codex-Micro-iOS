import Foundation

/// The joystick's four directions and the work each one starts.
///
/// The hardware's joystick invokes common Codex workflows — reviewing pull
/// requests, debugging, refactoring — without reaching for the mouse. Each
/// direction is a prompt the device sends on the user's behalf.
///
/// **These are prompts, not privileges.** A workflow spends exactly the same
/// capability as typing the words by hand, and the Mac resolves sandbox,
/// writable roots, and approval policy for it exactly as it would for any
/// other turn. That is why adding a direction is a UI change and not a
/// security review: the joystick cannot ask for anything the prompt sheet
/// could not.
///
/// The wording is deliberately imperative and scoped. A macro that expands to
/// "fix everything" is a macro whose blast radius the user cannot predict from
/// a flick of a thumb, and the whole point of the control is that it is used
/// without deliberation.
public enum JoystickWorkflow: String, CaseIterable, Sendable {
  case review
  case debug
  case refactor
  case explain

  /// Compass direction on the pad.
  public enum Direction: String, CaseIterable, Sendable {
    case up, right, down, left
  }

  public var direction: Direction {
    switch self {
    case .review: return .up
    case .debug: return .right
    case .refactor: return .down
    case .explain: return .left
    }
  }

  /// The label on the pad.
  public var title: String {
    switch self {
    case .review: return "Review"
    case .debug: return "Debug"
    case .refactor: return "Refactor"
    case .explain: return "Explain"
    }
  }

  /// The prompt sent to the selected agent.
  public var prompt: String {
    switch self {
    case .review:
      return
        "Review the current changes. Point out correctness problems, missing "
        + "tests, and anything that would surprise a reviewer. Do not change files."
    case .debug:
      return
        "Diagnose the current failure. Find the root cause and explain it before "
        + "proposing a fix."
    case .refactor:
      return
        "Suggest a refactor of the code you are working on. Explain what improves "
        + "and what risk it carries before changing anything."
    case .explain:
      return "Explain what you are currently doing and why, briefly."
    }
  }

  /// Every workflow needs the same capability as a typed prompt, because that
  /// is exactly what it is.
  public var requiredCapability: DeviceCapability { .runAgent }

  public static func workflow(for direction: Direction) -> JoystickWorkflow? {
    allCases.first { $0.direction == direction }
  }
}

extension JoystickWorkflow {
  /// Whether the joystick can be used right now, reusing the command keys'
  /// resolver so the pad and the keys can never disagree about availability.
  public static func availability(
    in surface: DeviceSurfaceState,
    capabilities: Set<DeviceCapability>
  ) -> CommandKeyAvailability {
    CommandKey.steer.availabilityIgnoringRunningTurn(
      in: surface, capabilities: capabilities)
  }
}

extension CommandKey {
  /// Availability without the running-turn requirement.
  ///
  /// A workflow starts a turn rather than steering one, so "that agent is not
  /// running" is the normal case for it rather than a refusal.
  func availabilityIgnoringRunningTurn(
    in surface: DeviceSurfaceState,
    capabilities: Set<DeviceCapability>
  ) -> CommandKeyAvailability {
    guard surface.isConnected else { return .notLive }
    guard let key = surface.selectedKey, key.isBound else { return .noSelection }
    guard key.freshness == .live else { return .notLive }
    guard capabilities.contains(.runAgent) else { return .notPermitted }
    return .available
  }
}
