import CompanionCrypto
import Foundation
import MacBridgeCore
import MacBridgeServer

/// Maps a startup failure onto a short, closed reason for the menu.
///
/// **"Unavailable" with no cause is undiagnosable.** The first launch of the
/// signed bridge reported exactly that, and nothing in the app or the system
/// log said which of identity, Keychain, authority, policy, or Codex had
/// refused — so the only way forward was to guess. One word fixes that.
///
/// Every value here is a compile-time constant drawn from an existing closed
/// enum. Nothing interpolates a path, an address, an identifier, a key, or a
/// system error string, so a screenshot of the menu still carries nothing
/// (plan §2 invariant 19).
public enum BridgeStartupReason {
  public static func describe(_ error: any Error) -> String {
    switch error {
    case let failure as BridgeIdentityError:
      return identity(failure)
    case let failure as DeviceGrantAuthorityError:
      return "authority.\(failure)"
    case let failure as CodexCompatibilityProbeError:
      return "codex.\(failure)"
    case let failure as EnclaveHostStatementSigner.Failure:
      switch failure {
      case .wrongIdentityRole: return "identity.wrongRole"
      }
    case let failure as BridgeCapabilityPolicyProbe.Failure:
      switch failure {
      case .profileTableEmpty: return "policy.empty"
      case .latticeFloorMoved: return "policy.floorMoved"
      }
    case let failure as BridgeAuthorityProvisioning.Failure:
      switch failure {
      case .authorityLost: return "authority.lost"
      }
    case let failure as BridgeCodexSupportProbe.Failure:
      switch failure {
      case .unsupported: return "codex.unsupported"
      }
    default:
      // Deliberately not the error's own description: a Foundation or
      // Security error interpolates paths and system strings, which is
      // exactly what must not reach a menu line.
      return "unclassified"
    }
  }

  /// Identity failures get their own mapping because they are the ones most
  /// likely to bite on a first signed launch: a signed app reaches a different
  /// Keychain domain than an unsigned binary, and a missing entitlement shows
  /// up here rather than as anything more obvious.
  private static func identity(_ failure: BridgeIdentityError) -> String {
    switch failure {
    case .attributeMismatch: return "identity.attributes"
    case .claimMissing: return "identity.claimMissing"
    case .claimStoreFailure: return "identity.claimStore"
    case .entitlementMissing: return "identity.entitlementMissing"
    case .cleanupIncomplete: return "identity.cleanup"
    case .duplicateIdentity: return "identity.duplicate"
    case .fingerprintMismatch: return "identity.fingerprint"
    case .identityLost: return "identity.lost"
    case .identityMissing: return "identity.missing"
    case .incompleteCreation: return "identity.incomplete"
    case .keyMultiplicity: return "identity.multiplicity"
    case .keyStoreFailure: return "identity.keyStore"
    case .privateKeyExportable: return "identity.exportable"
    case .publicKeyUnavailable: return "identity.publicKey"
    case .resetRefused: return "identity.resetRefused"
    case .rollbackFailure: return "identity.rollback"
    case .signatureFailure: return "identity.signature"
    }
  }
}
