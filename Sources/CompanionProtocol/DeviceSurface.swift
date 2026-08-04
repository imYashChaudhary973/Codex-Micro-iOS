import Foundation

/// The complete state of the device surface: six agent keys and the controls
/// around them.
///
/// This is derived state, not wire state. It exists so both endpoints — and
/// the tests — agree on exactly what the hardware would be showing, without
/// any of them owning a copy of the rules.
public struct DeviceSurfaceState: Equatable, Sendable {
  /// Always ``AgentKeyState/slotCount`` entries, in slot order.
  public let agentKeys: [AgentKeyState]
  /// Which slot the command keys act on, or `nil` when none is selected.
  public let selectedSlot: Int?
  /// Whether an authenticated session exists at all.
  public let isConnected: Bool

  public init(agentKeys: [AgentKeyState], selectedSlot: Int?, isConnected: Bool) {
    self.agentKeys = agentKeys
    self.selectedSlot = selectedSlot
    self.isConnected = isConnected
  }

  /// Everything dark and nothing selected.
  public static let disconnected = DeviceSurfaceState(
    agentKeys: (0..<AgentKeyState.slotCount).map {
      AgentKeyState(
        slot: $0, threadID: nil, projectID: nil, activity: .unknown,
        freshness: .disconnected)
    },
    selectedSlot: nil,
    isConnected: false
  )

  /// The currently selected key, if any.
  public var selectedKey: AgentKeyState? {
    guard let selectedSlot, agentKeys.indices.contains(selectedSlot) else { return nil }
    return agentKeys[selectedSlot]
  }
}

/// Builds the surface state from observed threads.
///
/// **The staleness budget is the whole point of this type.** Invariant 1 says
/// a key never lies, and the only way to keep that promise is to decide, on a
/// clock, when "what we last heard" stops counting as "what is true". The
/// budget makes that decision once, in one place, rather than leaving each
/// view to guess.
public struct DeviceSurfaceProjection: Sendable {
  /// How long a key keeps claiming to be live after the last update.
  ///
  /// Short enough that a user does not act on a dead reading, long enough
  /// that an idle-but-healthy connection does not flicker. A turn produces
  /// events far more often than this; silence for this long means something
  /// is wrong even if the socket is technically open.
  public static let defaultFreshnessBudget: TimeInterval = 12

  private let budget: TimeInterval

  public init(freshnessBudget: TimeInterval = DeviceSurfaceProjection.defaultFreshnessBudget) {
    self.budget = freshnessBudget
  }

  /// Projects the surface for a set of slot bindings.
  ///
  /// - Parameters:
  ///   - bindings: Thread identifier per slot; `nil` for an empty slot. Longer
  ///     arrays are truncated and shorter ones padded, so the surface always
  ///     has exactly six keys however the binding store is behaving.
  ///   - threads: The device's authorized view. A binding naming a thread that
  ///     is not here resolves to an unknown-but-bound key rather than being
  ///     dropped: the slot is still spoken for, and silently emptying it would
  ///     hide a revocation behind what looks like an unused key.
  ///   - lastUpdate: When the feed last delivered. `nil` means never.
  ///   - now: Injected clock.
  ///   - isConnected: Whether an authenticated session exists.
  public func project(
    bindings: [String?],
    threads: [ObservedThreadState],
    lastUpdate: Date?,
    now: Date,
    isConnected: Bool,
    selectedSlot: Int? = nil
  ) -> DeviceSurfaceState {
    guard isConnected else { return .disconnected }

    let freshness: AgentKeyFreshness
    if let lastUpdate, now.timeIntervalSince(lastUpdate) <= budget {
      freshness = .live
    } else {
      // Never having heard anything is stale, not live. A key that has never
      // been told anything must not present as authoritative.
      freshness = .stale
    }

    let byID = Dictionary(
      threads.map { ($0.threadID, $0) },
      uniquingKeysWith: { first, _ in
        first
      })

    let keys = (0..<AgentKeyState.slotCount).map { slot -> AgentKeyState in
      guard slot < bindings.count, let threadID = bindings[slot] else {
        return .unbound(slot: slot)
      }
      guard let thread = byID[threadID] else {
        return AgentKeyState(
          slot: slot, threadID: threadID, projectID: nil, activity: .unknown,
          freshness: freshness)
      }
      return .derive(slot: slot, thread: thread, freshness: freshness)
    }

    let selection = selectedSlot.flatMap { slot -> Int? in
      guard keys.indices.contains(slot), keys[slot].isBound else { return nil }
      return slot
    }
    return DeviceSurfaceState(
      agentKeys: keys, selectedSlot: selection, isConnected: true)
  }
}
