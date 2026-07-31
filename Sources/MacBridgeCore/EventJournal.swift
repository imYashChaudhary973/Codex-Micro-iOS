import Foundation

public struct SequencedJournalEvent<Event: Sendable>: Sendable {
  public let sequence: UInt64
  public let createdAt: Date
  public let event: Event

  public init(sequence: UInt64, createdAt: Date, event: Event) {
    self.sequence = sequence
    self.createdAt = createdAt
    self.event = event
  }
}

extension SequencedJournalEvent: Equatable where Event: Equatable {}

public enum JournalReplay<Event: Sendable>: Sendable {
  case events([SequencedJournalEvent<Event>])
  case snapshotRequired(latestSequence: UInt64)
}

extension JournalReplay: Equatable where Event: Equatable {}

public enum EventJournalError: Error, Equatable, Sendable {
  case invalidCapacity
  case cursorAhead(latestSequence: UInt64)
  case sequenceExhausted
}

public actor EventJournal<Event: Sendable> {
  private let capacity: Int
  private var entries: [SequencedJournalEvent<Event>] = []
  private var nextSequence: UInt64 = 1

  public init(capacity: Int) throws {
    guard capacity > 0 else { throw EventJournalError.invalidCapacity }
    self.capacity = capacity
  }

  @discardableResult
  public func append(_ event: Event, createdAt: Date = Date()) throws
    -> SequencedJournalEvent<Event>
  {
    guard nextSequence < UInt64.max else { throw EventJournalError.sequenceExhausted }
    let entry = SequencedJournalEvent(
      sequence: nextSequence,
      createdAt: createdAt,
      event: event
    )
    nextSequence += 1
    entries.append(entry)
    if entries.count > capacity {
      entries.removeFirst(entries.count - capacity)
    }
    return entry
  }

  public func replay(after cursor: UInt64) throws -> JournalReplay<Event> {
    let latestSequence = nextSequence - 1
    guard cursor <= latestSequence else {
      throw EventJournalError.cursorAhead(latestSequence: latestSequence)
    }
    guard let oldestSequence = entries.first?.sequence else {
      return .events([])
    }
    if cursor < oldestSequence - 1 {
      return .snapshotRequired(latestSequence: latestSequence)
    }
    return .events(entries.filter { $0.sequence > cursor })
  }

  public func latestSequence() -> UInt64 {
    nextSequence - 1
  }
}
