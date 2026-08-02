import CompanionProtocol
import CryptoKit
import Foundation

/// Closed device-grant-authority failure vocabulary. Carries no content.
///
/// Every storage, codec, and actor failure in the grant authority surfaces
/// as exactly one of these cases; no free-form diagnostic exists on any
/// path (plan §2 invariant 19).
public enum DeviceGrantAuthorityError: Error, Equatable, Sendable {
  /// The authority is in its latched closed state: a load, persist,
  /// rollback, or overflow failure occurred and every operation is denied
  /// until a successful reload. Callers must treat this as LAN-disable.
  case authorityUnavailable
  /// The store reported explicit-empty where prior in-memory authority
  /// state exists. The persisted authority is missing; fails closed.
  case authorityMissing
  /// The persisted blob is malformed, truncated, oversized, carries an
  /// unknown version/domain, has trailing bytes, or contains duplicate
  /// device records. Fails closed (ADR §10).
  case corruptAuthority
  /// More than one persisted authority item exists. Fails closed.
  case duplicateAuthorityItem
  /// Reading or writing the persistent store failed. Fails closed; no
  /// memory-only fallback (plan §2 invariant 15).
  case storageUnavailable
  /// The persisted authority sequence regressed against in-memory state.
  /// Rollback fails closed (ADR §10 anti-rollback).
  case rollbackDetected
  /// A revision, view-epoch, host-generation, or authority-sequence
  /// increment would overflow. The authority is disabled instead of
  /// wrapping (plan §9 counter widths).
  case counterOverflow
  /// The encoded authority blob would exceed the 64 KiB bound. The
  /// mutation is denied and the prior state remains authoritative.
  case authorityOversized
  /// A grant record field violates its declared bounds.
  case invalidGrant
  /// No grant record exists for the requested device.
  case deviceUnknown
  /// The device carries a revocation tombstone. Tombstones are permanent:
  /// the device ID may never be re-granted (threat model §5).
  case deviceRevoked
  /// The device is expired, either past its expiry instant or through an
  /// explicit expiry tombstone. Distinct from revocation by plan §4
  /// (Step 2.4b) so callers surface the correct closed reason.
  case deviceExpired
  /// A grant already exists for the device ID being added.
  case duplicateDevice
}

/// Field bounds for authoritative grant records and the authority blob.
public enum GrantAuthorityLimits {
  /// Maximum encoded authority blob size in bytes (64 KiB, ADR §10).
  public static let maximumBlobByteCount = 64 * 1024
  /// Maximum UTF-8 byte count of one opaque project ID.
  public static let maxProjectIDBytes = 128
  /// Maximum number of allowlisted projects per device.
  public static let maxProjectCount = 256
}

/// Permanent tombstone recording why a grant was terminated.
///
/// A tombstoned device ID is never re-granted; a new pairing must create a
/// new device ID (threat model §5). The kind selects the closed denial
/// reason surfaced to authorization checks.
public struct DeviceGrantTombstone: Equatable, Hashable, Sendable {
  /// Closed tombstone-kind vocabulary.
  public enum Kind: String, CaseIterable, Equatable, Hashable, Sendable {
    /// The Mac user revoked the device.
    case revoked
    /// The grant was expired, actively or past its expiry instant.
    case expired
  }

  /// Why the grant was terminated.
  public let kind: Kind
  /// Display-neutral termination instant in epoch seconds.
  public let tombstonedAtEpochSeconds: UInt64

  /// Creates a tombstone record.
  public init(kind: Kind, tombstonedAtEpochSeconds: UInt64) {
    self.kind = kind
    self.tombstonedAtEpochSeconds = tombstonedAtEpochSeconds
  }
}

/// One authoritative Mac-stored device grant record (plan Step 2.4b).
///
/// This record is the Mac's authority over a paired device: a grant
/// presented by the phone is evidence, never authorization (plan §2
/// invariant 1). All timestamps are display-neutral `UInt64` epoch
/// seconds; the record carries no name, endpoint, or user-derived value.
public struct AuthoritativeDeviceGrant: Equatable, Sendable {
  /// Opaque paired-device identifier bound at pairing.
  public let deviceID: UUID
  /// The device's long-term public key, exactly 65 X9.63 bytes.
  public let devicePublicKey: Data
  /// When the grant was created, in epoch seconds.
  public let createdAtEpochSeconds: UInt64
  /// When the device last authenticated, in epoch seconds.
  public let lastSeenAtEpochSeconds: UInt64
  /// Granted capabilities (Phase 1 closed vocabulary).
  public let capabilities: Set<DeviceCapability>
  /// Opaque allowlisted project IDs; empty by default (plan §9).
  public let permittedProjectIDs: Set<String>
  /// Ceiling for the device's mobile action profile.
  public let actionProfileCeiling: MobileActionProfile
  /// Per-device grant revision; starts at 1 and increments on every
  /// grant/scope/revocation mutation (plan §9).
  public let grantRevision: UInt64
  /// Per-device authorized-view epoch; starts at 1 and advances on every
  /// scope-affecting change (plan §9).
  public let authorizedViewEpoch: UInt64
  /// Optional expiry instant in epoch seconds; the grant is denied at and
  /// after this instant.
  public let expiresAtEpochSeconds: UInt64?
  /// Permanent termination tombstone, or `nil` while the grant is live.
  public let tombstone: DeviceGrantTombstone?

  /// Whether the record carries a revocation tombstone.
  public var isRevoked: Bool {
    tombstone?.kind == .revoked
  }

  /// The persisted revocation instant, or `nil` unless this record carries
  /// a revocation tombstone.
  public var revokedAtEpochSeconds: UInt64? {
    guard tombstone?.kind == .revoked else { return nil }
    return tombstone?.tombstonedAtEpochSeconds
  }

  /// The persisted explicit-expiry instant, or `nil` unless this record
  /// carries an expiry tombstone.
  public var expiredAtEpochSeconds: UInt64? {
    guard tombstone?.kind == .expired else { return nil }
    return tombstone?.tombstonedAtEpochSeconds
  }

  /// Creates a validated record; bound violations throw
  /// ``DeviceGrantAuthorityError/invalidGrant``.
  public init(
    deviceID: UUID,
    devicePublicKey: Data,
    createdAtEpochSeconds: UInt64,
    lastSeenAtEpochSeconds: UInt64,
    capabilities: Set<DeviceCapability>,
    permittedProjectIDs: Set<String>,
    actionProfileCeiling: MobileActionProfile,
    grantRevision: UInt64,
    authorizedViewEpoch: UInt64,
    expiresAtEpochSeconds: UInt64?,
    tombstone: DeviceGrantTombstone?
  ) throws {
    guard devicePublicKey.count == SecureTransportLimits.publicKeyByteCount,
      devicePublicKey.first == 0x04,
      (try? P256.Signing.PublicKey(x963Representation: devicePublicKey)) != nil,
      lastSeenAtEpochSeconds >= createdAtEpochSeconds,
      expiresAtEpochSeconds.map({ $0 > createdAtEpochSeconds }) ?? true,
      tombstone.map({ $0.tombstonedAtEpochSeconds >= createdAtEpochSeconds }) ?? true,
      grantRevision >= 1,
      authorizedViewEpoch >= 1,
      permittedProjectIDs.count <= GrantAuthorityLimits.maxProjectCount,
      permittedProjectIDs.allSatisfy(Self.isValidProjectID)
    else {
      throw DeviceGrantAuthorityError.invalidGrant
    }
    self.deviceID = deviceID
    self.devicePublicKey = devicePublicKey
    self.createdAtEpochSeconds = createdAtEpochSeconds
    self.lastSeenAtEpochSeconds = lastSeenAtEpochSeconds
    self.capabilities = capabilities
    self.permittedProjectIDs = permittedProjectIDs
    self.actionProfileCeiling = actionProfileCeiling
    self.grantRevision = grantRevision
    self.authorizedViewEpoch = authorizedViewEpoch
    self.expiresAtEpochSeconds = expiresAtEpochSeconds
    self.tombstone = tombstone
  }

  private static func isValidProjectID(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= GrantAuthorityLimits.maxProjectIDBytes
      && Data(value.utf8) == Data(value.precomposedStringWithCanonicalMapping.utf8)
      && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }
}

/// The complete in-memory authority state mirrored by the persisted blob.
///
/// The state is replaced as one value per mutation and encoded as one
/// canonical blob, so authority can never be observed partially written
/// (ADR §10).
struct GrantAuthorityState: Equatable, Sendable {
  /// Host-wide generation; starts at 1 and changes only for global
  /// invalidation (plan §9).
  let hostGeneration: UInt64
  /// Monotonic anti-rollback write sequence; increments on every persisted
  /// mutation. `0` only for the never-persisted fresh-install state.
  let authoritySequence: UInt64
  /// Grant records keyed by device ID.
  let grants: [UUID: AuthoritativeDeviceGrant]

  /// The never-persisted valid-empty fresh-install state.
  static let freshInstall = GrantAuthorityState(
    hostGeneration: 1,
    authoritySequence: 0,
    grants: [:]
  )

}
