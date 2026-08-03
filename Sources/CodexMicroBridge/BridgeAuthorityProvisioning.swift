import Foundation
import MacBridgeCore

/// Creates the grant-authority item once, on first install.
///
/// `DataProtectionKeychainGrantStore` deliberately refuses to create its own
/// item: absence throws `authorityMissing`, and its own comment records that
/// "only explicit first-install provisioning may create the item". That rule
/// exists so an authority that *vanishes* — a wiped Keychain, a restored
/// machine, a rolled-back backup — reads as loss rather than being silently
/// recreated with an empty grant set, which would drop every revocation the
/// authority held.
///
/// Nothing performed that provisioning step, so a freshly installed bridge
/// could never start: the listener's grant-authority probe refused, LAN stayed
/// off, and pairing — the only thing that creates a grant — was unreachable.
/// A perfect chicken-and-egg.
///
/// **The hard part is distinguishing "never existed" from "existed and is
/// gone".** The Keychain cannot tell them apart; both are
/// `errSecItemNotFound`. So provisioning records a marker when it runs, and
/// the two cases separate cleanly:
///
/// - no marker, no item → first install. Provision an empty authority.
/// - marker, no item → the authority was lost. Fail closed, loudly.
/// - item present → nothing to do, whatever the marker says.
///
/// The marker holds no secret and no authority state. It answers exactly one
/// question — "have we ever provisioned on this machine?" — and losing it can
/// only cause a *safe* misclassification in one direction, because an existing
/// item is never touched.
public enum BridgeAuthorityProvisioning {
  /// Raised when the authority is gone after having been provisioned.
  public enum Failure: Error, Equatable, Sendable {
    /// The item is missing but this machine provisioned one before. The
    /// grants, revocations, and anti-rollback sequence it held are gone;
    /// re-pairing every device is the only recovery, and that is a decision
    /// for the user rather than something to paper over at startup.
    case authorityLost
  }

  public static let markerKey = "com.codexmicro.bridge.authority-provisioned"

  /// Result of the provisioning check, for diagnostics.
  public enum Outcome: String, Sendable {
    case alreadyPresent
    case provisioned
  }

  /// Ensures the authority item exists, creating it only on a genuine first
  /// install. Must run **before** `DeviceGrantAuthority` is constructed.
  @discardableResult
  public static func ensureProvisioned(
    store: any GrantAuthorityStorage = DataProtectionKeychainGrantStore(),
    hasProvisionedBefore: () -> Bool = { UserDefaults.standard.bool(forKey: markerKey) },
    recordProvisioned: () -> Void = { UserDefaults.standard.set(true, forKey: markerKey) }
  ) throws -> Outcome {
    do {
      _ = try store.load()
      // An item exists. Record the marker if it is absent, so a machine
      // provisioned before this code shipped is not later misread as a first
      // install if its item ever disappears.
      recordProvisioned()
      return .alreadyPresent
    } catch DeviceGrantAuthorityError.authorityMissing {
      guard !hasProvisionedBefore() else {
        throw Failure.authorityLost
      }
      // First install: write the empty authority. The store's own add path
      // accepts an empty blob precisely for this, and verifies what it
      // persisted before returning.
      try store.replace(blob: Data())
      recordProvisioned()
      return .provisioned
    }
  }
}
