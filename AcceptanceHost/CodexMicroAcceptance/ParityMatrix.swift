import CompanionProtocol
import Foundation

/// The Phase 3 parity matrix: every control on the Codex Micro, exercised
/// against a real Mac over real Wi-Fi.
///
/// **This checks parity, not correctness.** The protocol underneath is covered
/// by 1085 deterministic tests and a physical Phase 2 acceptance. What no test
/// can answer is whether the *device* behaves like the device: whether a key
/// tells the truth while you are looking at it, whether a control that cannot
/// act says so before you press it, and whether the thing stays usable when
/// the network does not.
///
/// Each case therefore names an observation a person makes, not an assertion a
/// machine makes. A case that could be automated belongs in the unit suite,
/// and most of them already are.
public enum ParityGate: String, CaseIterable, Identifiable, Sendable {
  case agentKeysReflectRealActivity
  case keysGoStaleRatherThanLying
  case bindingsSurviveReconnect
  case unavailableControlsSayWhy
  case promptReachesTheSelectedAgent
  case reasoningDialClampsAndDefers
  case joystickWorkflowsRun
  case newChatCreatesAThread
  case approvalShowsBeforeItResolves
  case pushToTalkStaysOnDevice
  case remappingCannotGrantPower

  public var id: String { rawValue }
}

public struct ParityCase: Identifiable, Sendable {
  public let gate: ParityGate
  public let title: String
  /// The property that would be false if this case failed.
  public let proves: String
  public let procedure: [String]
  /// What the phone can check about itself before the physical run.
  public let precondition: (@Sendable () -> AcceptanceReadiness)?

  public var id: String { gate.rawValue }
}

extension ParityCase {
  public static let matrix: [ParityCase] = [
    ParityCase(
      gate: .agentKeysReflectRealActivity,
      title: "Agent keys reflect real activity",
      proves: "The six keys show what the Mac's agents are actually doing, and "
        + "change within a glance of the agent changing.",
      procedure: [
        "Pair, grant a project, and start turns in three threads on the Mac.",
        "Confirm three keys light and the rest stay dark.",
        "Interrupt one turn on the Mac; confirm its key turns to waiting.",
        "Let one finish; confirm its key turns to finished and stops pulsing.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .keysGoStaleRatherThanLying,
      title: "Keys go stale rather than lying",
      proves: "A key never keeps claiming a state after the Mac stops telling it one.",
      procedure: [
        "With agents running, disable Wi-Fi on the Mac.",
        "Confirm the keys dim and the banner says the status may be out of date.",
        "Confirm the keys keep their last colour rather than blanking.",
        "Confirm every command key becomes unavailable while stale.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .bindingsSurviveReconnect,
      title: "Bindings survive a reconnect",
      proves: "The agent on key 3 is still on key 3 after the app restarts.",
      procedure: [
        "Note which agent occupies each key.",
        "Force-quit the app and relaunch it.",
        "Confirm every key holds the same agent, in the same position.",
        "Confirm a newly started thread fills an empty key without moving the others.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .unavailableControlsSayWhy,
      title: "Unavailable controls say why",
      proves: "A control the device may not use is visibly unavailable before "
        + "it is pressed, and names its reason.",
      procedure: [
        "Reduce the device's grant on the Mac to observe-only.",
        "Confirm Stop and Steer go dim while Prev and Next stay usable.",
        "Confirm VoiceOver reads the reason, not just the label.",
        "Deselect every agent; confirm the acting keys say to select one.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .promptReachesTheSelectedAgent,
      title: "A prompt reaches the selected agent",
      proves: "The prompt goes to the agent on the selected key, never to "
        + "whichever conversation the Mac happens to be focused on.",
      procedure: [
        "Select key 2 on the phone; focus a different thread on the Mac.",
        "Send a prompt from the phone.",
        "Confirm it landed in key 2's thread and not the Mac's focused one.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .reasoningDialClampsAndDefers,
      title: "The dial clamps and says when it applies",
      proves: "The dial cannot request a level the host does not offer, and "
        + "states that a change lands on the next turn.",
      procedure: [
        "With a turn running, confirm the dial reads 'applies after the running turn'.",
        "Turn it to the highest offered level and confirm it stops there.",
        "Start a new turn and confirm the Mac ran it at that effort.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .joystickWorkflowsRun,
      title: "Joystick workflows run",
      proves: "Each direction sends its scoped prompt to the selected agent.",
      procedure: [
        "Select an idle agent and flick each of the four directions in turn.",
        "Confirm each starts a turn whose prompt matches the documented wording.",
        "Confirm Review did not modify any file.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .newChatCreatesAThread,
      title: "New chat creates a thread on the Mac's terms",
      proves: "The phone can create a thread only where the Mac allows, and "
        + "never names a path.",
      procedure: [
        "With the Mac opted out, confirm New is refused.",
        "Opt in and grant .startThread; confirm New creates a thread.",
        "Confirm the thread's working directory is the Mac's project root.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .approvalShowsBeforeItResolves,
      title: "An approval is shown before it is resolved",
      proves: "It is impossible to approve something the screen did not show.",
      procedure: [
        "Trigger an approval on the Mac in a granted project.",
        "Confirm the phone shows it above the accept and reject buttons.",
        "With the Mac not disclosing content, confirm the phone says the request is not shown.",
        "Approve, and confirm the Mac executed exactly once.",
        "Resolve a second approval on the Mac first, then press approve on the phone; "
          + "confirm it is refused as no longer waiting.",
      ],
      precondition: nil
    ),
    ParityCase(
      gate: .pushToTalkStaysOnDevice,
      title: "Push-to-talk stays on device",
      proves: "Dictation is recognised locally and no audio leaves the phone.",
      procedure: [
        "Put the phone in airplane mode with Wi-Fi on but no internet route.",
        "Hold Talk and dictate a prompt.",
        "Confirm a transcript appears, proving recognition was local.",
        "Confirm the resulting prompt is indistinguishable from a typed one on the Mac.",
      ],
      precondition: { AcceptancePreconditions.readiness(for: .enclaveIdentityAndReinstall) }
    ),
    ParityCase(
      gate: .remappingCannotGrantPower,
      title: "Remapping cannot grant power",
      proves: "Moving an action to another key does not change what it costs.",
      procedure: [
        "With the grant lacking .approve, map Approve onto key 1.",
        "Confirm the remap screen marks it not permitted.",
        "Confirm the key is present but unusable on the pad.",
        "Grant .approve on the Mac and confirm the same key becomes usable without remapping again.",
      ],
      precondition: nil
    ),
  ]
}
