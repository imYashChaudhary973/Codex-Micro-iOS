import CompanionProtocol
import Foundation

/// The grant authority is the only source of a device's disclosure scope.
///
/// Unknown, revoked, and expired devices are collapsed onto
/// ``ObservationScopeResult/notObservable`` because the observation path does
/// not need to distinguish them — the session layer already holds the
/// device's liveness and closes the connection with the correct reason. Every
/// other authority failure propagates, so an unavailable authority denies
/// disclosure instead of falling back to anything (plan §2 invariant 15).
extension DeviceGrantAuthority: ObservationScopeProviding {
  public func observationScope(deviceID: UUID) throws -> ObservationScopeResult {
    do {
      let scope = AuthorizedViewScope(grant: try authoritativeGrant(deviceID: deviceID))
      return scope.allowsObservation ? .scoped(scope) : .notObservable
    } catch DeviceGrantAuthorityError.deviceUnknown {
      return .notObservable
    } catch DeviceGrantAuthorityError.deviceRevoked {
      return .notObservable
    } catch DeviceGrantAuthorityError.deviceExpired {
      return .notObservable
    }
  }
}

/// The bridge assembly supplies the unfiltered snapshot the broker filters.
///
/// This is the only unfiltered read on the observation path, and its result
/// never leaves ``DeviceObservationBroker`` unfiltered.
extension CodexBridgeAssembly: ObservationSnapshotProviding {
  public func currentObservationSnapshot() async -> CompanionStateSnapshot {
    await snapshot()
  }
}
