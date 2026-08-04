import Foundation

/// What one of the six agent keys shows.
///
/// The physical Codex Micro lights six frosted keys to report whether each
/// bound agent is thinking, running, waiting, or finished. This derives the
/// same reading from the observation payloads the Mac already sends, so the
/// phone and the hardware agree without the protocol carrying a presentation
/// concept.
///
/// **Activity and freshness are separate on purpose.** Phase 3 invariant 1
/// says a key never lies about state, and the way a status display lies is by
/// continuing to show its last value after it stopped being told anything.
/// Folding "the agent is running" and "we last heard thirty seconds ago" into
/// one enum makes that failure unrepresentable in the type and inevitable in
/// the code. Kept apart, a stale key can show what it last knew *and* that it
/// is no longer sure, which is what the hardware's own LED does when the host
/// disconnects.
public enum AgentKeyActivity: String, Codable, Equatable, CaseIterable, Sendable {
  /// A turn is running. The hardware pulses here.
  case working
  /// The agent stopped and wants something from you.
  case waiting
  /// The last turn completed cleanly.
  case finished
  /// The last turn failed, or the thread is in error.
  case failed
  /// A bound thread whose state the Mac has not described.
  case unknown
}

/// How much the displayed activity can be trusted.
public enum AgentKeyFreshness: String, Codable, Equatable, CaseIterable, Sendable {
  /// The Mac is connected and this is current.
  case live
  /// Last known value, but the feed has gone quiet past its budget. The key
  /// keeps its colour and dims, because "it was running when we last heard"
  /// is more useful than blank — and less misleading than pretending it is
  /// still true.
  case stale
  /// No authenticated session. Nothing is known about any agent.
  case disconnected
}

/// One key's complete display state.
public struct AgentKeyState: Equatable, Sendable {
  /// Slot index, `0..<AgentKeyState.slotCount`.
  public let slot: Int
  /// The thread this slot is bound to, or `nil` when the slot is empty.
  public let threadID: String?
  /// The project the bound thread belongs to. Present only when bound.
  public let projectID: String?
  public let activity: AgentKeyActivity
  public let freshness: AgentKeyFreshness

  /// The device has exactly six agent keys.
  public static let slotCount = 6

  public init(
    slot: Int,
    threadID: String?,
    projectID: String?,
    activity: AgentKeyActivity,
    freshness: AgentKeyFreshness
  ) {
    self.slot = slot
    self.threadID = threadID
    self.projectID = projectID
    self.activity = activity
    self.freshness = freshness
  }

  /// An empty slot on a live connection: dark, and not claiming otherwise.
  public static func unbound(slot: Int) -> AgentKeyState {
    AgentKeyState(
      slot: slot, threadID: nil, projectID: nil, activity: .unknown, freshness: .live)
  }

  /// Whether the key is bound to a thread at all.
  public var isBound: Bool { threadID != nil }

  /// Whether pressing this key can do anything.
  ///
  /// A disconnected key is inert rather than hidden, because the hardware's
  /// keys do not disappear when the cable is unplugged — they stop glowing.
  public var isActionable: Bool { isBound && freshness != .disconnected }
}

extension AgentKeyState {
  /// Derives the key state for one observed thread.
  ///
  /// The mapping is deliberately conservative. `activeTurnID` is what makes a
  /// key say "working": a thread can be `active` while its turn has already
  /// finished, and showing a pulsing key for an agent that is done is exactly
  /// the lie invariant 1 forbids.
  public static func derive(
    slot: Int,
    thread: ObservedThreadState,
    freshness: AgentKeyFreshness
  ) -> AgentKeyState {
    AgentKeyState(
      slot: slot,
      threadID: thread.threadID,
      projectID: thread.projectID,
      activity: AgentKeyActivity.derive(from: thread),
      freshness: freshness
    )
  }

}

extension AgentKeyActivity {
  /// The activity a thread's observed state implies.
  public static func derive(from thread: ObservedThreadState) -> AgentKeyActivity {
    // Error beats everything: a failed thread must not read as finished
    // merely because its last turn happens to have completed earlier.
    if thread.status == .error { return .failed }

    if thread.activeTurnID != nil {
      // A turn is in flight. Its own status still decides, because a turn can
      // be active-but-failed and the key must not pulse for it.
      switch thread.lastTurnStatus {
      case .failed: return .failed
      case .interrupted: return .waiting
      default: return .working
      }
    }

    switch thread.lastTurnStatus {
    case .completed: return .finished
    case .failed: return .failed
    // Interrupted with no active turn means the agent stopped and is waiting
    // for you to say what happens next — the hardware's "waiting" colour.
    case .interrupted: return .waiting
    case .inProgress:
      // In progress with no active turn is a contradiction; the Mac's view
      // and ours disagree. Unknown is the honest answer, not a guess.
      return .unknown
    case .unknown, .none:
      return thread.status == .idle ? .waiting : .unknown
    }
  }
}
