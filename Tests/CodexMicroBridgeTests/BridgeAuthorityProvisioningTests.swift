import Foundation
import MacBridgeCore
import XCTest

@testable import CodexMicroBridge

/// First-install provisioning of the grant authority.
///
/// The store refuses to create its own item on purpose, so that an authority
/// which *vanishes* reads as loss rather than being silently recreated empty —
/// which would drop every revocation it held. Nothing performed the
/// provisioning step, so a freshly installed bridge could never start: the
/// grant-authority probe refused, LAN stayed off, and pairing (the only thing
/// that creates a grant) was unreachable.
///
/// These tests pin the distinction that makes the fix safe: "never existed"
/// and "existed and is gone" look identical to the Keychain, and only the
/// marker separates them.
final class BridgeAuthorityProvisioningTests: XCTestCase {

  func testAFirstInstallProvisionsAnEmptyAuthority() throws {
    let store = ProvisioningStore(state: .missing)
    var recorded = false

    let outcome = try BridgeAuthorityProvisioning.ensureProvisioned(
      store: store,
      hasProvisionedBefore: { false },
      recordProvisioned: { recorded = true }
    )

    XCTAssertEqual(outcome, .provisioned)
    XCTAssertEqual(store.written, Data(), "provisioning wrote a non-empty authority")
    XCTAssertTrue(recorded, "the marker was not recorded, so a later loss reads as first install")
  }

  /// The critical case. A missing item on a machine that has provisioned
  /// before means the grants, revocations, and anti-rollback sequence are
  /// gone. Recreating an empty authority here would silently un-revoke every
  /// device that was ever revoked.
  func testALostAuthorityFailsClosedRatherThanBeingRecreated() {
    let store = ProvisioningStore(state: .missing)

    XCTAssertThrowsError(
      try BridgeAuthorityProvisioning.ensureProvisioned(
        store: store,
        hasProvisionedBefore: { true },
        recordProvisioned: {}
      )
    ) { error in
      XCTAssertEqual(error as? BridgeAuthorityProvisioning.Failure, .authorityLost)
    }
    XCTAssertNil(store.written, "a lost authority was overwritten")
  }

  /// An existing authority is never touched, whatever the marker says.
  func testAnExistingAuthorityIsLeftAlone() throws {
    let store = ProvisioningStore(state: .present(Data([0x01, 0x02])))

    for hasProvisioned in [true, false] {
      let outcome = try BridgeAuthorityProvisioning.ensureProvisioned(
        store: store,
        hasProvisionedBefore: { hasProvisioned },
        recordProvisioned: {}
      )
      XCTAssertEqual(outcome, .alreadyPresent)
      XCTAssertNil(store.written, "an existing authority was rewritten")
    }
  }

  /// A machine provisioned before this code shipped has an item but no
  /// marker. Recording it on the way past is what stops a later loss being
  /// misread as a first install.
  func testAnExistingAuthorityBackfillsTheMarker() throws {
    let store = ProvisioningStore(state: .present(Data([0x09])))
    var recorded = false

    _ = try BridgeAuthorityProvisioning.ensureProvisioned(
      store: store,
      hasProvisionedBefore: { false },
      recordProvisioned: { recorded = true }
    )

    XCTAssertTrue(recorded)
  }

  /// A storage failure that is not "missing" must propagate untouched. It is
  /// not a first install and it is not loss; guessing either way would be
  /// wrong.
  func testAnUnreadableAuthorityPropagatesRatherThanProvisioning() {
    let store = ProvisioningStore(state: .failing(.corruptAuthority))

    XCTAssertThrowsError(
      try BridgeAuthorityProvisioning.ensureProvisioned(
        store: store,
        hasProvisionedBefore: { false },
        recordProvisioned: {}
      )
    ) { error in
      XCTAssertEqual(error as? DeviceGrantAuthorityError, .corruptAuthority)
    }
    XCTAssertNil(store.written, "an unreadable authority was overwritten")
  }
}

/// A store whose load outcome is injectable, recording what was written.
private final class ProvisioningStore: GrantAuthorityStorage, @unchecked Sendable {
  enum State {
    case missing
    case present(Data)
    case failing(DeviceGrantAuthorityError)
  }

  private let state: State
  private(set) var written: Data?

  init(state: State) {
    self.state = state
  }

  func load() throws -> GrantAuthorityLoadResult {
    switch state {
    case .missing: throw DeviceGrantAuthorityError.authorityMissing
    case .present(let blob): return blob.isEmpty ? .empty : .blob(blob)
    case .failing(let error): throw error
    }
  }

  func replace(blob: Data) throws {
    written = blob
  }
}
