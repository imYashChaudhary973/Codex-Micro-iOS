import Foundation

/// Closed availability state of the grant authority.
public enum GrantAuthorityAvailability: Equatable, Sendable {
  /// The authority loaded and is serving authorization state.
  case available
  /// The authority is latched closed for the given reason; every
  /// operation is denied and callers must treat LAN as disabled.
  case unavailable(DeviceGrantAuthorityError)
}

/// Complete authority view for the Mac administration UI **only**.
///
/// This is the single bulk read of authority state, including tombstones.
/// It exists for grant administration on the Mac and must never be exposed
/// to network sessions or any device-scoped path; devices read exclusively
/// through ``DeviceGrantHandle``/device-scoped accessors.
public struct GrantAuthorityAdministrationSnapshot: Equatable, Sendable {
  /// Host-wide generation.
  public let hostGeneration: UInt64
  /// Monotonic anti-rollback authority write sequence.
  public let authoritySequence: UInt64
  /// Every grant record including tombstones, ordered by device ID.
  public let grants: [AuthoritativeDeviceGrant]
}

/// Device-scoped read/touch handle bound to one authenticated device.
///
/// Session code holds a handle created from the authenticated device ID
/// and can reach exactly that device's authority — the handle exposes no
/// device-ID parameter, so reading or mutating another device's record
/// through it is structurally impossible (plan Step 2.4b isolation rule).
public struct DeviceGrantHandle: Sendable {
  private let authority: DeviceGrantAuthority
  private let deviceID: UUID

  init(authority: DeviceGrantAuthority, deviceID: UUID) {
    self.authority = authority
    self.deviceID = deviceID
  }

  /// The bound device's current authoritative record, only while the
  /// grant is live (not revoked, not expired).
  public func authoritativeGrant() async throws -> AuthoritativeDeviceGrant {
    try await authority.authoritativeGrant(deviceID: deviceID)
  }

  /// The bound device's effective Phase 1 policy grant, only while the
  /// grant is live.
  public func effectiveGrant() async throws -> DeviceGrant {
    try await authority.effectiveGrant(deviceID: deviceID)
  }

  /// Records that the bound device authenticated now.
  @discardableResult
  public func touchLastSeen() async throws -> AuthoritativeDeviceGrant {
    try await authority.touchLastSeen(deviceID: deviceID)
  }
}

/// The authoritative Mac-stored device-grant authority (plan Step 2.4b).
///
/// This actor is the single API for session authentication and command
/// authorization: it owns the persisted authority blob (ADR §10), every
/// grant mutation, and every authorization lookup. Mutations follow
/// persist-before-visible — the whole canonical blob is atomically
/// replaced in storage **first**, and only then does the new state become
/// visible to lookups — so authorization changes are linearizable (plan §2
/// invariant 11) and a lookup can never observe unpersisted authority.
///
/// Failure is latched closed: a load failure, persist failure, detected
/// rollback, or counter overflow moves the authority to
/// ``GrantAuthorityAvailability/unavailable(_:)`` where every operation
/// throws ``DeviceGrantAuthorityError/authorityUnavailable`` until a
/// successful ``reloadFromStore()``. Callers must treat that state as
/// LAN-disable (plan §2 invariant 15). There is no memory-only fallback
/// and no free-form logging.
public actor DeviceGrantAuthority {
  private let storage: any GrantAuthorityStorage
  private let clock: @Sendable () -> UInt64
  private var state: GrantAuthorityState
  private var latchedFailure: DeviceGrantAuthorityError?

  /// Opens the authority over `storage`, loading persisted state
  /// immediately.
  ///
  /// An explicit-empty store marker is the valid fresh-install state and
  /// leaves the authority available with zero grants. A missing item,
  /// duplicate, undecodable or oversized blob, and any store read failure
  /// latch the authority unavailable instead (LAN-disable); the reason is
  /// visible through ``availability()``. Loading is synchronous by
  /// contract: storage implementations must be thread-safe and require no
  /// async isolation.
  ///
  /// - Parameters:
  ///   - storage: The single synchronous storage seam this actor owns.
  ///   - clock: Injected display-neutral epoch-seconds clock.
  public init(
    storage: any GrantAuthorityStorage,
    clock: @escaping @Sendable () -> UInt64 = {
      UInt64(max(0, Date().timeIntervalSince1970.rounded(.down)))
    }
  ) {
    self.storage = storage
    self.clock = clock
    do {
      self.state = try Self.loadState(from: storage)
      self.latchedFailure = nil
    } catch {
      self.state = .freshInstall
      self.latchedFailure = Self.closedFailure(error)
    }
  }

  // MARK: - Availability

  /// The authority's current closed availability state.
  public func availability() -> GrantAuthorityAvailability {
    if let latchedFailure {
      return .unavailable(latchedFailure)
    }
    return .available
  }

  /// Re-reads persisted state, clearing a latched failure on success.
  ///
  /// The decoded authority sequence must not regress against in-memory
  /// state: a lower sequence latches
  /// ``DeviceGrantAuthorityError/rollbackDetected`` and an explicit-empty
  /// store where in-memory state was already persisted latches
  /// ``DeviceGrantAuthorityError/authorityMissing`` (ADR §10
  /// anti-rollback). Both remain LAN-disable states.
  public func reloadFromStore() throws {
    do {
      switch try storage.load() {
      case .empty:
        guard state.authoritySequence == 0 else {
          throw DeviceGrantAuthorityError.authorityMissing
        }
        state = .freshInstall
      case .blob(let blob):
        let decoded = try GrantAuthorityBlobCodec.decode(blob)
        guard decoded.authoritySequence >= state.authoritySequence else {
          throw DeviceGrantAuthorityError.rollbackDetected
        }
        if decoded.authoritySequence == state.authoritySequence {
          guard decoded == state else {
            throw DeviceGrantAuthorityError.rollbackDetected
          }
        }
        state = decoded
      }
      latchedFailure = nil
    } catch {
      let failure = Self.closedFailure(error)
      latchedFailure = failure
      throw failure
    }
  }

  // MARK: - Administration mutations (Mac UI)

  /// Persists a new grant from completed pairing output.
  ///
  /// The record starts at grant revision 1 and authorized-view epoch 1
  /// with an empty project allowlist unless the Mac user explicitly
  /// selected projects (plan §9). A device ID that already exists is
  /// rejected — including tombstoned IDs, which are permanently burned:
  /// re-granting requires a new pairing that creates a new device ID.
  @discardableResult
  public func addGrant(
    deviceID: UUID,
    devicePublicKey: Data,
    capabilities: Set<DeviceCapability> = [.view],
    permittedProjectIDs: Set<String> = [],
    actionProfileCeiling: MobileActionProfile = .observe,
    expiresAtEpochSeconds: UInt64? = nil
  ) throws -> AuthoritativeDeviceGrant {
    let now = clock()
    let next = try mutate { state in
      if let existing = state.grants[deviceID] {
        throw Self.duplicateGrantFailure(for: existing)
      }
      if let expiresAtEpochSeconds {
        guard expiresAtEpochSeconds > now else {
          throw DeviceGrantAuthorityError.invalidGrant
        }
      }
      let record = try AuthoritativeDeviceGrant(
        deviceID: deviceID,
        devicePublicKey: devicePublicKey,
        createdAtEpochSeconds: now,
        lastSeenAtEpochSeconds: now,
        capabilities: capabilities,
        permittedProjectIDs: permittedProjectIDs,
        actionProfileCeiling: actionProfileCeiling,
        grantRevision: 1,
        authorizedViewEpoch: 1,
        expiresAtEpochSeconds: expiresAtEpochSeconds,
        tombstone: nil
      )
      return state.replacing(record)
    }
    return try publishedRecord(deviceID: deviceID, in: next)
  }

  /// Revokes a device with a permanent tombstone.
  ///
  /// Bumps the grant revision and the authorized-view epoch (revocation
  /// is scope-affecting, plan §9). Permitted on live and passively
  /// expired records; an existing tombstone is permanent and re-surfaces
  /// its own closed reason.
  @discardableResult
  public func revoke(deviceID: UUID) throws -> AuthoritativeDeviceGrant {
    try tombstone(deviceID: deviceID, kind: .revoked)
  }

  /// Expires a device with a permanent tombstone.
  ///
  /// Identical semantics to ``revoke(deviceID:)`` — revision bump,
  /// authorized-view epoch bump, permanent tombstone — but lookups
  /// surface the distinct closed reason
  /// ``DeviceGrantAuthorityError/deviceExpired``. Passive clock-checked
  /// lookups deny immediately at the expiry instant without mutating;
  /// the expiry/session scheduler introduced with active sessions must call
  /// this method to persist the tombstone before closing those sessions.
  /// This actor deliberately owns no wall-clock sleeping task.
  @discardableResult
  public func expire(deviceID: UUID) throws -> AuthoritativeDeviceGrant {
    try tombstone(deviceID: deviceID, kind: .expired)
  }

  /// Reduces the device's opaque project allowlist.
  ///
  /// The replacement must be a strict subset of the current allowlist;
  /// expansion requires a separately reviewed Mac-administration path.
  /// Scope reduction advances both the grant revision and authorized-view
  /// epoch (plan §9), forcing queued-data purge and a fresh filtered
  /// snapshot downstream.
  @discardableResult
  public func reduceScope(
    deviceID: UUID,
    permittedProjectIDs: Set<String>
  ) throws -> AuthoritativeDeviceGrant {
    let now = clock()
    return try mutateActiveRecord(deviceID: deviceID, now: now) { record in
      guard permittedProjectIDs.isStrictSubset(of: record.permittedProjectIDs) else {
        throw DeviceGrantAuthorityError.invalidGrant
      }
      return try AuthoritativeDeviceGrant(
        deviceID: record.deviceID,
        devicePublicKey: record.devicePublicKey,
        createdAtEpochSeconds: record.createdAtEpochSeconds,
        lastSeenAtEpochSeconds: record.lastSeenAtEpochSeconds,
        capabilities: record.capabilities,
        permittedProjectIDs: permittedProjectIDs,
        actionProfileCeiling: record.actionProfileCeiling,
        grantRevision: try Self.bumped(record.grantRevision),
        authorizedViewEpoch: try Self.bumped(record.authorizedViewEpoch),
        expiresAtEpochSeconds: record.expiresAtEpochSeconds,
        tombstone: nil
      )
    }
  }

  /// Replaces the device's capabilities and mobile-action-profile ceiling.
  ///
  /// Bumps the grant revision. The authorized-view epoch also advances
  /// exactly when membership of `.view` changes, because that changes
  /// whether any authorized project view exists; other action-capability
  /// and profile changes leave the view epoch unchanged (plan §9).
  @discardableResult
  public func amendCapabilities(
    deviceID: UUID,
    capabilities: Set<DeviceCapability>,
    actionProfileCeiling: MobileActionProfile
  ) throws -> AuthoritativeDeviceGrant {
    let now = clock()
    return try mutateActiveRecord(deviceID: deviceID, now: now) { record in
      let viewMembershipChanged =
        record.capabilities.contains(.view)
        != capabilities.contains(.view)
      return try AuthoritativeDeviceGrant(
        deviceID: record.deviceID,
        devicePublicKey: record.devicePublicKey,
        createdAtEpochSeconds: record.createdAtEpochSeconds,
        lastSeenAtEpochSeconds: record.lastSeenAtEpochSeconds,
        capabilities: capabilities,
        permittedProjectIDs: record.permittedProjectIDs,
        actionProfileCeiling: actionProfileCeiling,
        grantRevision: try Self.bumped(record.grantRevision),
        authorizedViewEpoch: viewMembershipChanged
          ? try Self.bumped(record.authorizedViewEpoch) : record.authorizedViewEpoch,
        expiresAtEpochSeconds: record.expiresAtEpochSeconds,
        tombstone: nil
      )
    }
  }

  /// Advances the host-wide generation for global invalidation only
  /// (plan §9). Per-device revisions are unchanged.
  @discardableResult
  public func advanceHostGeneration() throws -> UInt64 {
    try mutate { state in
      GrantAuthorityState(
        hostGeneration: try Self.bumped(state.hostGeneration),
        authoritySequence: state.authoritySequence,
        grants: state.grants
      )
    }.hostGeneration
  }

  // MARK: - Device-scoped operations

  /// Creates the device-scoped handle for an authenticated device ID.
  ///
  /// The device ID must come from session authentication, never from a
  /// message payload; the handle then structurally confines the session
  /// to that device's authority.
  public nonisolated func deviceHandle(for deviceID: UUID) -> DeviceGrantHandle {
    DeviceGrantHandle(authority: self, deviceID: deviceID)
  }

  /// The current authoritative record for an authenticated device.
  ///
  /// Returns the record only while the grant is live: revoked and
  /// expired tombstones and a passed expiry instant (injected clock)
  /// surface their distinct closed reasons instead.
  public func authoritativeGrant(deviceID: UUID) throws -> AuthoritativeDeviceGrant {
    try requireAvailable()
    return try Self.liveRecord(in: state, deviceID: deviceID, now: clock())
  }

  /// The effective Phase 1 policy grant for an authenticated device,
  /// derived from the live authoritative record.
  public func effectiveGrant(deviceID: UUID) throws -> DeviceGrant {
    try authoritativeGrant(deviceID: deviceID).effectivePolicyGrant
  }

  /// Records that the authenticated device was seen now.
  ///
  /// Updates only the display-neutral last-seen instant; the grant
  /// revision and authorized-view epoch are unchanged because no
  /// authorization content changes. The write still persists before it is
  /// visible and advances the authority sequence.
  @discardableResult
  public func touchLastSeen(deviceID: UUID) throws -> AuthoritativeDeviceGrant {
    let now = clock()
    let next = try mutate { state in
      let record = try Self.liveRecord(in: state, deviceID: deviceID, now: now)
      return state.replacing(
        try AuthoritativeDeviceGrant(
          deviceID: record.deviceID,
          devicePublicKey: record.devicePublicKey,
          createdAtEpochSeconds: record.createdAtEpochSeconds,
          lastSeenAtEpochSeconds: max(now, record.lastSeenAtEpochSeconds),
          capabilities: record.capabilities,
          permittedProjectIDs: record.permittedProjectIDs,
          actionProfileCeiling: record.actionProfileCeiling,
          grantRevision: record.grantRevision,
          authorizedViewEpoch: record.authorizedViewEpoch,
          expiresAtEpochSeconds: record.expiresAtEpochSeconds,
          tombstone: nil
        ))
    }
    return try publishedRecord(deviceID: deviceID, in: next)
  }

  /// The current host-wide generation.
  public func currentHostGeneration() throws -> UInt64 {
    try requireAvailable()
    return state.hostGeneration
  }

  /// The complete authority view for the Mac administration UI only.
  /// Never expose this snapshot to a network or device-scoped path.
  public func macAdministrationSnapshot() throws -> GrantAuthorityAdministrationSnapshot {
    try requireAvailable()
    return GrantAuthorityAdministrationSnapshot(
      hostGeneration: state.hostGeneration,
      authoritySequence: state.authoritySequence,
      grants: state.grants.values.sorted { $0.deviceID.uuidString < $1.deviceID.uuidString }
    )
  }

  // MARK: - Persist-before-visible core

  private func requireAvailable() throws {
    guard latchedFailure == nil else {
      throw DeviceGrantAuthorityError.authorityUnavailable
    }
  }

  private func mutate(
    _ transform: (GrantAuthorityState) throws -> GrantAuthorityState
  ) throws -> GrantAuthorityState {
    try requireAvailable()
    let transformed: GrantAuthorityState
    do {
      transformed = try transform(state)
    } catch let failure as DeviceGrantAuthorityError {
      if failure == .counterOverflow {
        latchedFailure = .counterOverflow
      }
      throw failure
    }
    guard state.authoritySequence < UInt64.max else {
      latchedFailure = .counterOverflow
      throw DeviceGrantAuthorityError.counterOverflow
    }
    let next = GrantAuthorityState(
      hostGeneration: transformed.hostGeneration,
      authoritySequence: state.authoritySequence + 1,
      grants: transformed.grants
    )
    let blob = try GrantAuthorityBlobCodec.encode(next)
    do {
      try storage.replace(blob: blob)
    } catch {
      let failure = Self.closedFailure(error)
      latchedFailure = failure
      throw failure
    }
    state = next
    return next
  }

  private func publishedRecord(
    deviceID: UUID,
    in state: GrantAuthorityState
  ) throws -> AuthoritativeDeviceGrant {
    guard let record = state.grants[deviceID] else {
      latchedFailure = .corruptAuthority
      throw DeviceGrantAuthorityError.corruptAuthority
    }
    return record
  }

  private func mutateActiveRecord(
    deviceID: UUID,
    now: UInt64,
    _ transform: (AuthoritativeDeviceGrant) throws -> AuthoritativeDeviceGrant
  ) throws -> AuthoritativeDeviceGrant {
    let next = try mutate { state in
      let record = try Self.liveRecord(in: state, deviceID: deviceID, now: now)
      return state.replacing(try transform(record))
    }
    return try publishedRecord(deviceID: deviceID, in: next)
  }

  private func tombstone(
    deviceID: UUID,
    kind: DeviceGrantTombstone.Kind
  ) throws -> AuthoritativeDeviceGrant {
    let now = clock()
    let next = try mutate { state in
      guard let record = state.grants[deviceID] else {
        throw DeviceGrantAuthorityError.deviceUnknown
      }
      if let existing = record.tombstone {
        throw Self.tombstoneFailure(existing)
      }
      return state.replacing(
        try AuthoritativeDeviceGrant(
          deviceID: record.deviceID,
          devicePublicKey: record.devicePublicKey,
          createdAtEpochSeconds: record.createdAtEpochSeconds,
          lastSeenAtEpochSeconds: record.lastSeenAtEpochSeconds,
          capabilities: record.capabilities,
          permittedProjectIDs: record.permittedProjectIDs,
          actionProfileCeiling: record.actionProfileCeiling,
          grantRevision: try Self.bumped(record.grantRevision),
          authorizedViewEpoch: try Self.bumped(record.authorizedViewEpoch),
          expiresAtEpochSeconds: record.expiresAtEpochSeconds,
          tombstone: DeviceGrantTombstone(
            kind: kind,
            tombstonedAtEpochSeconds: max(now, record.createdAtEpochSeconds)
          )
        ))
    }
    return try publishedRecord(deviceID: deviceID, in: next)
  }

  // MARK: - Pure helpers

  private static func loadState(
    from storage: any GrantAuthorityStorage
  ) throws -> GrantAuthorityState {
    switch try storage.load() {
    case .empty:
      return .freshInstall
    case .blob(let blob):
      return try GrantAuthorityBlobCodec.decode(blob)
    }
  }

  private static func liveRecord(
    in state: GrantAuthorityState,
    deviceID: UUID,
    now: UInt64
  ) throws -> AuthoritativeDeviceGrant {
    guard let record = state.grants[deviceID] else {
      throw DeviceGrantAuthorityError.deviceUnknown
    }
    if let tombstone = record.tombstone {
      throw tombstoneFailure(tombstone)
    }
    if let expiresAt = record.expiresAtEpochSeconds, now >= expiresAt {
      throw DeviceGrantAuthorityError.deviceExpired
    }
    return record
  }

  private static func tombstoneFailure(
    _ tombstone: DeviceGrantTombstone
  ) -> DeviceGrantAuthorityError {
    switch tombstone.kind {
    case .revoked: .deviceRevoked
    case .expired: .deviceExpired
    }
  }

  private static func duplicateGrantFailure(
    for existing: AuthoritativeDeviceGrant
  ) -> DeviceGrantAuthorityError {
    if let tombstone = existing.tombstone {
      return tombstoneFailure(tombstone)
    }
    return .duplicateDevice
  }

  private static func bumped(_ counter: UInt64) throws -> UInt64 {
    guard counter < UInt64.max else {
      throw DeviceGrantAuthorityError.counterOverflow
    }
    return counter + 1
  }

  private static func closedFailure(_ error: any Error) -> DeviceGrantAuthorityError {
    (error as? DeviceGrantAuthorityError) ?? .storageUnavailable
  }
}

extension GrantAuthorityState {
  /// Returns a copy with `record` replacing the entry for its device ID.
  /// The authority sequence is advanced by the persist step, not here.
  fileprivate func replacing(_ record: AuthoritativeDeviceGrant) -> GrantAuthorityState {
    var grants = self.grants
    grants[record.deviceID] = record
    return GrantAuthorityState(
      hostGeneration: hostGeneration,
      authoritySequence: authoritySequence,
      grants: grants
    )
  }
}
