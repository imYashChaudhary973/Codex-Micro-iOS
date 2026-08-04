import Foundation

/// Content schemas for the opaque payload ``SecureObservationDelivery``
/// carries (plan Step 2.8).
///
/// Step 2.2 deliberately left that payload as bounded opaque bytes; these
/// types bind it. They are **host-originated only** — a device never sends
/// them — but they decode as strictly as every other secure message so the
/// device side of the contract is equally closed.
///
/// Two deliberate exclusions:
///
/// - **No approval content.** Phase 2 negotiates no approval feature and its
///   gateway rejects `resolveApproval` (plan §2 invariant 17), so a device
///   that cannot act on an approval is told nothing about one. Approval
///   request IDs, digests, item/turn identifiers, and available decisions
///   therefore never reach the observation surface. Phase 4 defines that
///   surface together with the device-bound user-presence assertion.
/// - **No global sequence.** Every sequence here is the device's own
///   authorized-view value. The host's journal sequence never travels,
///   because its movement would reveal activity in projects the device is
///   not allowed to see (plan §2 invariant 5).
public enum SecureObservationLimits {
  /// Maximum threads in one filtered snapshot.
  public static let maxSnapshotThreadCount = 128
  /// Maximum events in one delivered batch.
  public static let maxEventBatchCount = 64
  /// Maximum UTF-8 byte count of an opaque thread identifier.
  public static let maxThreadIDBytes = 128
  /// Maximum UTF-8 byte count of an opaque turn identifier.
  public static let maxTurnIDBytes = 128
  /// Maximum UTF-8 byte count of an opaque project identifier. Matches the
  /// grant authority's own project-ID bound.
  public static let maxProjectIDBytes = 128
}

/// One thread as an authorized device may see it.
///
/// This is a bounded, strictly decoded projection of the Phase 1
/// ``CompanionThreadState``; the Phase 1 type stays off the security surface
/// because it accepts unknown fields. The project ID is present because it
/// is already inside the device's own allowlist — a thread the device may
/// not see never becomes an ``ObservedThreadState`` at all.
public struct ObservedThreadState: Codable, Equatable, Sendable {
  public let threadID: String
  public let projectID: String
  public let status: CompanionThreadStatus
  public let activeTurnID: String?
  public let lastTurnID: String?
  public let lastTurnStatus: CompanionTurnStatus?

  public init(
    threadID: String,
    projectID: String,
    status: CompanionThreadStatus,
    activeTurnID: String?,
    lastTurnID: String?,
    lastTurnStatus: CompanionTurnStatus?
  ) throws {
    try requireBoundedText(
      threadID, maxUTF8: SecureObservationLimits.maxThreadIDBytes, field: "threadID")
    try requireBoundedText(
      projectID, maxUTF8: SecureObservationLimits.maxProjectIDBytes, field: "projectID")
    for (turnID, field) in [(activeTurnID, "activeTurnID"), (lastTurnID, "lastTurnID")] {
      if let turnID {
        try requireBoundedText(
          turnID, maxUTF8: SecureObservationLimits.maxTurnIDBytes, field: field)
      }
    }
    self.threadID = threadID
    self.projectID = projectID
    self.status = status
    self.activeTurnID = activeTurnID
    self.lastTurnID = lastTurnID
    self.lastTurnStatus = lastTurnStatus
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      threadID: container.decode(String.self, forKey: .threadID),
      projectID: container.decode(String.self, forKey: .projectID),
      status: container.decode(CompanionThreadStatus.self, forKey: .status),
      activeTurnID: container.decodeIfPresent(String.self, forKey: .activeTurnID),
      lastTurnID: container.decodeIfPresent(String.self, forKey: .lastTurnID),
      lastTurnStatus: container.decodeIfPresent(CompanionTurnStatus.self, forKey: .lastTurnStatus)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case threadID
    case projectID
    case status
    case activeTurnID
    case lastTurnID
    case lastTurnStatus
  }
}

/// The complete filtered view of everything an authorized device may see at
/// one instant. It is the payload of a `.snapshot` delivery.
public struct SecureObservationSnapshot: Codable, Equatable, Sendable {
  /// When the snapshot was taken, as display-neutral epoch seconds. Phase 2
  /// carries every instant this way so the wire never depends on a
  /// `Date`-encoding strategy chosen at the call site.
  public let generatedAtEpochSeconds: UInt64
  public let threads: [ObservedThreadState]
  /// What this device is permitted to do.
  ///
  /// Carried on the snapshot rather than announced separately because it
  /// rides the machinery that already exists: an authorization change moves
  /// the device's authorized-view epoch, which forces a fresh snapshot. So
  /// the capability set and the threads it applies to always arrive together
  /// and can never describe different moments.
  ///
  /// The device needs this to show an unavailable control as unavailable
  /// rather than as one that fails when pressed (Phase 3 invariant 2). It
  /// discloses nothing new: it is a statement about what the Mac would
  /// already refuse.
  public let capabilities: Set<DeviceCapability>

  public init(
    generatedAtEpochSeconds: UInt64,
    threads: [ObservedThreadState],
    capabilities: Set<DeviceCapability> = []
  ) throws {
    guard threads.count <= SecureObservationLimits.maxSnapshotThreadCount else {
      throw SecureWireValidationError.invalidField(name: "threads")
    }
    let identifiers = Set(threads.map(\.threadID))
    guard identifiers.count == threads.count else {
      throw SecureWireValidationError.invalidField(name: "threads")
    }
    guard threads.map(\.threadID) == threads.map(\.threadID).sorted() else {
      throw SecureWireValidationError.invalidField(name: "threads")
    }
    self.generatedAtEpochSeconds = generatedAtEpochSeconds
    self.threads = threads
    self.capabilities = capabilities
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      generatedAtEpochSeconds: container.decode(UInt64.self, forKey: .generatedAtEpochSeconds),
      threads: container.decode([ObservedThreadState].self, forKey: .threads),
      // Absent means "no capabilities stated", not "all capabilities". A
      // device that cannot tell what it may do must assume it may do nothing.
      capabilities: try container.decodeIfPresent(
        Set<DeviceCapability>.self, forKey: .capabilities) ?? []
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case generatedAtEpochSeconds
    case threads
    case capabilities
  }
}

/// Closed observation-event vocabulary. Phase 2 emits exactly one kind: a
/// content-free tick saying an authorized thread changed and a fresh read is
/// worth taking.
public enum SecureObservationEventKind: String, Codable, CaseIterable, Sendable {
  case threadUpdated
}

/// One event in the device's own authorized-view sequence namespace.
public struct SecureObservationEvent: Codable, Equatable, Sendable {
  public let sequence: UInt64
  public let kind: SecureObservationEventKind
  public let threadID: String
  public let projectID: String

  public init(
    sequence: UInt64,
    kind: SecureObservationEventKind,
    threadID: String,
    projectID: String
  ) throws {
    guard sequence >= 1 else {
      throw SecureWireValidationError.invalidField(name: "sequence")
    }
    try requireBoundedText(
      threadID, maxUTF8: SecureObservationLimits.maxThreadIDBytes, field: "threadID")
    try requireBoundedText(
      projectID, maxUTF8: SecureObservationLimits.maxProjectIDBytes, field: "projectID")
    self.sequence = sequence
    self.kind = kind
    self.threadID = threadID
    self.projectID = projectID
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(
      sequence: container.decode(UInt64.self, forKey: .sequence),
      kind: container.decode(SecureObservationEventKind.self, forKey: .kind),
      threadID: container.decode(String.self, forKey: .threadID),
      projectID: container.decode(String.self, forKey: .projectID)
    )
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case sequence
    case kind
    case threadID
    case projectID
  }
}

/// One bounded, strictly increasing run of authorized events. It is the
/// payload of an `.event` delivery, and the delivery's cursor carries the
/// last sequence in the batch.
public struct SecureObservationEventBatch: Codable, Equatable, Sendable {
  public let events: [SecureObservationEvent]

  public init(events: [SecureObservationEvent]) throws {
    guard (1...SecureObservationLimits.maxEventBatchCount).contains(events.count) else {
      throw SecureWireValidationError.invalidField(name: "events")
    }
    guard zip(events, events.dropFirst()).allSatisfy({ $0.sequence < $1.sequence }) else {
      throw SecureWireValidationError.invalidField(name: "events")
    }
    self.events = events
  }

  public init(from decoder: Decoder) throws {
    let container = try strictContainer(from: decoder, keyedBy: CodingKeys.self)
    try self.init(events: container.decode([SecureObservationEvent].self, forKey: .events))
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case events
  }
}
