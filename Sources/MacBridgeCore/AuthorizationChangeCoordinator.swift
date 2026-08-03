import CompanionProtocol
import Foundation

/// Which authorization change was committed.
public enum AuthorizationChangeKind: String, Equatable, CaseIterable, Sendable {
  case revoked
  case expired
  case scopeReduced
  case capabilitiesAmended
  /// Host-wide invalidation: every device must reauthenticate.
  case hostGenerationAdvanced
}

/// What the transport must do with a device's connections once the change has
/// committed and its data has been purged.
///
/// Both cases are terminal for the *current* session — plan §2 invariant 11
/// requires every affected pairing, handshaking, and authenticated connection
/// to be closed or reauthenticated. `reauthenticate` means the device keeps a
/// grant, so it may immediately open a new session under the new
/// authorization; `close` means it has none.
public enum AuthorizationConnectionAction: Equatable, Sendable {
  case close(SecureCloseReason)
  case reauthenticate
}

/// The complete, already-committed outcome of one authorization change.
public struct AuthorizationChangeOutcome: Equatable, Sendable {
  public let deviceID: UUID
  public let kind: AuthorizationChangeKind
  /// The device's grant revision after the commit.
  public let grantRevision: UInt64
  /// The device's authorized-view epoch after the commit.
  public let authorizedViewEpoch: UInt64
  /// The authority write sequence the commit published.
  public let authoritySequence: UInt64
  /// What the purge discarded from the device's observation state.
  public let observation: ObservationPurgeResult
  /// Read-cursor entries the purge dropped.
  public let discardedReadCursors: Int
  /// What the transport must now do with the device's connections.
  public let connectionAction: AuthorizationConnectionAction
}

/// Closed authorization-change failure vocabulary.
public enum AuthorizationChangeError: Error, Equatable, Sendable {
  /// The grant authority refused or could not commit the change. Nothing was
  /// purged and nothing was closed; the prior authorization remains in force.
  case commitFailed(DeviceGrantAuthorityError)
  /// The change committed but read-cursor state could not be purged. The
  /// authorization change stands — the caller must still close the device's
  /// connections — but stale read positions may remain on disk.
  case purgeIncomplete(DeviceReadCursorError)
}

/// Performs every Phase 2 authorization change in the one order that makes it
/// linearizable (plan §2 invariant 11):
///
/// 1. **Commit** the change in the grant authority, which persists the whole
///    canonical blob before the new revision becomes visible to any lookup.
/// 2. **Purge** the device's queued and retained observation data and its
///    now-unauthorized read positions.
/// 3. **Report** what the transport must do with the device's connections.
///
/// The order is structural, not a convention: this actor is the only place
/// the three steps appear together, and each step's result feeds the next.
/// Because the authority commit happens first and every reader — the broker,
/// the read-cursor store, the session coordinator — re-reads the authority
/// rather than caching it, a concurrent operation either completed under the
/// prior authorization before the commit or is denied after it. There is no
/// window in which the old authorization is still honoured.
///
/// The coordinator deliberately does **not** close connections itself. The
/// transport owns connections and `MacBridgeServer` does not import this
/// module; the caller that owns both applies the returned action.
public actor AuthorizationChangeCoordinator {
  private let authority: DeviceGrantAuthority
  private let broker: DeviceObservationBroker
  private let readCursors: DeviceReadCursorStore

  public init(
    authority: DeviceGrantAuthority,
    broker: DeviceObservationBroker,
    readCursors: DeviceReadCursorStore
  ) {
    self.authority = authority
    self.broker = broker
    self.readCursors = readCursors
  }

  /// Revokes a device permanently and purges everything it held.
  public func revoke(deviceID: UUID) async throws -> AuthorizationChangeOutcome {
    try await terminate(deviceID: deviceID, kind: .revoked)
  }

  /// Expires a device permanently and purges everything it held.
  ///
  /// This is the API the active-session expiry scheduler must call: it
  /// persists the expiry tombstone *before* the affected sessions are closed,
  /// which is what the grant authority's own contract requires.
  public func expire(deviceID: UUID) async throws -> AuthorizationChangeOutcome {
    try await terminate(deviceID: deviceID, kind: .expired)
  }

  /// Reduces a device's project scope.
  ///
  /// The device keeps its grant, so its retained history is dropped, its
  /// sequence namespace restarts under the new authorized-view epoch, its
  /// out-of-scope read positions are purged, and its session must
  /// reauthenticate.
  public func reduceScope(
    deviceID: UUID,
    permittedProjectIDs: Set<String>
  ) async throws -> AuthorizationChangeOutcome {
    let record = try await commit {
      try await self.authority.reduceScope(
        deviceID: deviceID, permittedProjectIDs: permittedProjectIDs)
    }
    return try await purgeRetaining(deviceID: deviceID, kind: .scopeReduced, record: record)
  }

  /// Replaces a device's capabilities and mobile-action-profile ceiling.
  ///
  /// Losing `.view` also moves the authorized-view epoch, so the same purge
  /// applies; either way the session must reauthenticate, because Step 2.6
  /// denies continued use on any counter change.
  public func amendCapabilities(
    deviceID: UUID,
    capabilities: Set<DeviceCapability>,
    actionProfileCeiling: MobileActionProfile
  ) async throws -> AuthorizationChangeOutcome {
    let record = try await commit {
      try await self.authority.amendCapabilities(
        deviceID: deviceID,
        capabilities: capabilities,
        actionProfileCeiling: actionProfileCeiling
      )
    }
    return try await purgeRetaining(
      deviceID: deviceID, kind: .capabilitiesAmended, record: record)
  }

  /// Advances the host-wide generation, invalidating every device at once.
  ///
  /// Per-device revisions are unchanged; the host generation alone denies
  /// continued use of every existing session. Every known device's
  /// observation state is purged before the caller closes their connections.
  public func invalidateAllDevices() async throws -> [AuthorizationChangeOutcome] {
    let snapshot: GrantAuthorityAdministrationSnapshot
    do {
      _ = try await authority.advanceHostGeneration()
      snapshot = try await authority.macAdministrationSnapshot()
    } catch let error as DeviceGrantAuthorityError {
      throw AuthorizationChangeError.commitFailed(error)
    }

    var outcomes: [AuthorizationChangeOutcome] = []
    for grant in snapshot.grants {
      let observation = await broker.applyCommittedAuthorization(deviceID: grant.deviceID)
      outcomes.append(
        AuthorizationChangeOutcome(
          deviceID: grant.deviceID,
          kind: .hostGenerationAdvanced,
          grantRevision: grant.grantRevision,
          authorizedViewEpoch: grant.authorizedViewEpoch,
          authoritySequence: snapshot.authoritySequence,
          observation: observation,
          discardedReadCursors: 0,
          connectionAction: observation.retainsObservation
            ? .reauthenticate : .close(.authorizationChanged)
        )
      )
    }
    return outcomes
  }

  // MARK: - Commit, then purge, then report

  private func terminate(
    deviceID: UUID,
    kind: AuthorizationChangeKind
  ) async throws -> AuthorizationChangeOutcome {
    let record = try await commit {
      switch kind {
      case .revoked: try await self.authority.revoke(deviceID: deviceID)
      default: try await self.authority.expire(deviceID: deviceID)
      }
    }

    let observation = await broker.applyCommittedAuthorization(deviceID: deviceID)
    let discarded = try await purgeAllReadCursors(deviceID: deviceID)
    return AuthorizationChangeOutcome(
      deviceID: deviceID,
      kind: kind,
      grantRevision: record.grantRevision,
      authorizedViewEpoch: record.authorizedViewEpoch,
      authoritySequence: try await currentAuthoritySequence(),
      observation: observation,
      discardedReadCursors: discarded,
      connectionAction: .close(kind == .revoked ? .deviceRevoked : .grantExpired)
    )
  }

  private func purgeRetaining(
    deviceID: UUID,
    kind: AuthorizationChangeKind,
    record: AuthoritativeDeviceGrant
  ) async throws -> AuthorizationChangeOutcome {
    let observation = await broker.applyCommittedAuthorization(deviceID: deviceID)
    // A device that kept its grant but lost observation has no authorized
    // read position left, so the partial purge would have nothing to keep.
    guard observation.retainsObservation else {
      let discarded = try await purgeAllReadCursors(deviceID: deviceID)
      return AuthorizationChangeOutcome(
        deviceID: deviceID,
        kind: kind,
        grantRevision: record.grantRevision,
        authorizedViewEpoch: record.authorizedViewEpoch,
        authoritySequence: try await currentAuthoritySequence(),
        observation: observation,
        discardedReadCursors: discarded,
        connectionAction: .close(.authorizationChanged)
      )
    }
    let discarded: Int
    do {
      discarded = try await readCursors.purgeOutOfScope(deviceID: deviceID)
    } catch let error as DeviceReadCursorError {
      throw AuthorizationChangeError.purgeIncomplete(error)
    }
    return AuthorizationChangeOutcome(
      deviceID: deviceID,
      kind: kind,
      grantRevision: record.grantRevision,
      authorizedViewEpoch: record.authorizedViewEpoch,
      authoritySequence: try await currentAuthoritySequence(),
      observation: observation,
      discardedReadCursors: discarded,
      connectionAction: observation.retainsObservation
        ? .reauthenticate : .close(.authorizationChanged)
    )
  }

  private func purgeAllReadCursors(deviceID: UUID) async throws -> Int {
    let existing = (try? await readCursors.storedThreadCount(deviceID: deviceID)) ?? 0
    do {
      try await readCursors.purge(deviceID: deviceID)
    } catch let error as DeviceReadCursorError {
      throw AuthorizationChangeError.purgeIncomplete(error)
    }
    return existing
  }

  /// Runs the authority mutation, mapping every authority failure onto the
  /// closed ``AuthorizationChangeError/commitFailed(_:)`` case. A failure here
  /// means nothing committed, so nothing is purged and nothing is closed.
  private func commit(
    _ mutation: () async throws -> AuthoritativeDeviceGrant
  ) async throws -> AuthoritativeDeviceGrant {
    do {
      return try await mutation()
    } catch let error as DeviceGrantAuthorityError {
      throw AuthorizationChangeError.commitFailed(error)
    }
  }

  private func currentAuthoritySequence() async throws -> UInt64 {
    do {
      return try await authority.macAdministrationSnapshot().authoritySequence
    } catch let error as DeviceGrantAuthorityError {
      throw AuthorizationChangeError.commitFailed(error)
    }
  }
}
