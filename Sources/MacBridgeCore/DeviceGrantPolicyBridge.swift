/// Bridge from the Step 2.4b authoritative grant records to the Phase 1
/// capability policy. Policy logic itself lives only in
/// ``CapabilityPolicy``; this derivation adds no authorization decisions.
extension AuthoritativeDeviceGrant {
  /// The effective Phase 1 ``DeviceGrant`` derived from this
  /// authoritative record, for ``CapabilityPolicy/authorize(command:grant:resolvedProjectID:hostProfile:now:)``.
  ///
  /// Any tombstone — revocation or expiry — derives a revoked policy
  /// grant, so even a mis-plumbed caller that bypasses the live-record
  /// lookup fails closed in policy. Passive expiry of the optional expiry
  /// instant is enforced by the authority's clock-checked lookups, which
  /// refuse to return expired records at all.
  public var effectivePolicyGrant: DeviceGrant {
    DeviceGrant(
      deviceID: deviceID,
      capabilities: capabilities,
      permittedProjectIDs: permittedProjectIDs,
      actionProfile: actionProfileCeiling,
      isRevoked: tombstone != nil
    )
  }
}
