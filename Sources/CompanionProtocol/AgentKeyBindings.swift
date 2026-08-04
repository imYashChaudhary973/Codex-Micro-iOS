import Foundation

/// Which thread each of the six agent keys is bound to.
///
/// **A binding never moves on its own.** This is the single rule the type
/// exists to enforce, and it is worth stating plainly because every other
/// convenience argues against it: reordering keys so the busiest agent sits
/// first, compacting away a finished thread, swapping in a newer one — each is
/// individually reasonable and collectively fatal. The device's value is that
/// you reach for key 3 without looking. A key that silently rebinds while your
/// thumb is moving destroys that, and it does so exactly when you are busy
/// enough not to check.
///
/// So: automatic changes only ever *fill an empty slot*. Nothing else is
/// automatic. Rebinding and releasing are things the user does.
public struct AgentKeyBindings: Equatable, Sendable, Codable {
  /// Thread identifier per slot, `nil` for empty. Always exactly
  /// ``AgentKeyState/slotCount`` entries.
  public private(set) var slots: [String?]

  /// All slots empty.
  public static let empty = AgentKeyBindings()

  public init() {
    slots = Array(repeating: nil, count: AgentKeyState.slotCount)
  }

  /// Rebuilds from stored slots, normalising length and clearing duplicates.
  ///
  /// A duplicate is not merely untidy: two keys pointing at one thread means
  /// two keys light identically and one of them is a lie about how many agents
  /// you have. The first occurrence wins so the earlier, more established
  /// binding is the one kept.
  public init(slots: [String?]) {
    var normalised = Array(slots.prefix(AgentKeyState.slotCount))
    normalised.append(
      contentsOf: Array(
        repeating: nil, count: max(0, AgentKeyState.slotCount - normalised.count)))
    var seen = Set<String>()
    for index in normalised.indices {
      guard let threadID = normalised[index] else { continue }
      if threadID.isEmpty || !seen.insert(threadID).inserted {
        normalised[index] = nil
      }
    }
    self.slots = normalised
  }

  /// The thread bound to a slot, if any.
  public func threadID(at slot: Int) -> String? {
    guard slots.indices.contains(slot) else { return nil }
    return slots[slot]
  }

  /// The slot a thread occupies, if any.
  public func slot(of threadID: String) -> Int? {
    slots.firstIndex { $0 == threadID }
  }

  /// Every bound thread.
  public var boundThreadIDs: Set<String> { Set(slots.compactMap { $0 }) }

  /// The first empty slot, if there is one.
  public var firstEmptySlot: Int? { slots.firstIndex { $0 == nil } }

  /// Binds a thread to a slot, explicitly.
  ///
  /// Moving a thread that is already bound elsewhere clears its old slot, so a
  /// thread is never in two places. This is the user asking for it, which is
  /// the only circumstance under which a binding moves.
  public func binding(threadID: String, to slot: Int) -> AgentKeyBindings {
    guard slots.indices.contains(slot), !threadID.isEmpty else { return self }
    var next = slots
    if let existing = next.firstIndex(where: { $0 == threadID }) {
      next[existing] = nil
    }
    next[slot] = threadID
    return AgentKeyBindings(slots: next)
  }

  /// Empties a slot.
  public func releasing(slot: Int) -> AgentKeyBindings {
    guard slots.indices.contains(slot) else { return self }
    var next = slots
    next[slot] = nil
    return AgentKeyBindings(slots: next)
  }

  /// Fills empty slots from the device's authorized view.
  ///
  /// Only empty slots are touched. A thread already bound stays exactly where
  /// it is, including one that has finished or that the view no longer
  /// mentions — the slot is spoken for until the user says otherwise.
  ///
  /// Which threads get the empty slots matters when there are more than six:
  /// the ones that **want attention** win, because an agent that is waiting on
  /// you is the reason to look at the device at all, and a finished one is the
  /// reason not to. Ties break on the host's own ordering, which is stable
  /// across deliveries, so repeated reconciliation is idempotent rather than
  /// producing a different arrangement each time.
  public func filling(from threads: [ObservedThreadState]) -> AgentKeyBindings {
    guard firstEmptySlot != nil else { return self }
    let alreadyBound = boundThreadIDs
    let candidates =
      threads
      .filter { !alreadyBound.contains($0.threadID) }
      .enumerated()
      .sorted { left, right in
        let leftRank = Self.attentionRank(AgentKeyActivity.derive(from: left.element))
        let rightRank = Self.attentionRank(AgentKeyActivity.derive(from: right.element))
        if leftRank != rightRank { return leftRank < rightRank }
        return left.offset < right.offset
      }
      .map(\.element)

    var next = slots
    var remaining = candidates.makeIterator()
    for index in next.indices where next[index] == nil {
      guard let thread = remaining.next() else { break }
      next[index] = thread.threadID
    }
    return AgentKeyBindings(slots: next)
  }

  /// Lower sorts first. Waiting outranks working because a waiting agent is
  /// blocked on the user and a working one is not.
  static func attentionRank(_ activity: AgentKeyActivity) -> Int {
    switch activity {
    case .waiting: return 0
    case .failed: return 1
    case .working: return 2
    case .unknown: return 3
    case .finished: return 4
    }
  }
}
