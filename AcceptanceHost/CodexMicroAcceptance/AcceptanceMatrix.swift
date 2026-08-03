import Foundation

/// The Phase 2 physical acceptance matrix, exactly as plan §7 gate 13 fixes it.
///
/// **This file is a checklist, not a test suite.** Every case here needs a real
/// iPhone, a real Mac, and a real network; nothing in it can be proven by
/// building. What the host *can* do offline is check each case's deterministic
/// preconditions — see ``AcceptanceReadiness`` — so a run that fails tells you
/// whether it failed because the property is broken or because the harness was
/// never in a position to test it.
///
/// The distinction matters at a gate. "Did not run" and "passed" are different
/// answers, and a matrix that cannot tell them apart is worse than no matrix,
/// because it launders the first into the second.
public enum AcceptanceGate: String, CaseIterable, Identifiable, Sendable {
  case enclaveIdentityAndReinstall
  case pinnedSelfSignedWSS
  case pairingAndBonjour
  case ipChange
  case foregroundBackgroundReauth
  case macRestart
  case keychainLockAndReboot
  case tlsRotation
  case filteredObserveAndReplay
  case immediateRevocation
  case idempotentInterrupt

  public var id: String { rawValue }
}

/// One case: what it proves, how to run it, and what must already hold for the
/// run to mean anything.
public struct AcceptanceCase: Identifiable, Sendable {
  public let gate: AcceptanceGate
  /// Short title for the list.
  public let title: String
  /// The property the case exists to establish. Written as the thing that
  /// would be *false* if the case failed, so a failure reads as a claim
  /// withdrawn rather than a step skipped.
  public let proves: String
  /// The physical procedure. Ordered; each step is an action on a real device.
  public let procedure: [String]
  /// Whether a live Codex is required, as opposed to the fake app-server.
  ///
  /// Plan §7 gate 13 permits the fake app-server for the interrupt case unless
  /// a live Codex is separately approved, because a live turn consumes
  /// allowance and can modify a workspace.
  public let requiresLiveCodex: Bool

  public var id: String { gate.rawValue }
}

extension AcceptanceCase {
  /// The complete matrix. Order follows plan §7 gate 13.
  public static let matrix: [AcceptanceCase] = [
    AcceptanceCase(
      gate: .enclaveIdentityAndReinstall,
      title: "Secure Enclave identity survives reinstall",
      proves: "The device's long-term key is Enclave-backed and non-exportable, "
        + "and reinstalling the app does not silently mint a new one.",
      procedure: [
        "Pair the device and record the device identity fingerprint the Mac shows.",
        "Delete the app from the iPhone.",
        "Reinstall and launch it.",
        "Confirm the app reports the identity as lost rather than presenting a new key.",
        "Confirm the Mac still holds the old grant and refuses the reinstalled app.",
        "Re-pair, and confirm the Mac records a new grant revision rather than reusing the old.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .pinnedSelfSignedWSS,
      title: "Pinned self-signed WSS",
      proves: "The phone connects only to the exact SPKI it pinned at pairing, "
        + "and a different certificate is refused before any application data moves.",
      procedure: [
        "Pair, then connect normally and confirm the session authenticates.",
        "On the Mac, reset the TLS identity so a different key is served.",
        "Reconnect and confirm the phone refuses at TLS, not after.",
        "Confirm no observation batch or command crossed the refused connection.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .pairingAndBonjour,
      title: "Pairing over Bonjour with phrase confirmation",
      proves: "Discovery, the six-word phrase, and dual confirmation work over real "
        + "Wi-Fi, and the phrase shown on both ends is identical.",
      procedure: [
        "Enable LAN access from the Mac menu.",
        "Confirm the iPhone discovers exactly one _codexmicro._tcp service.",
        "Scan the pairing QR.",
        "Read the six-word phrase on both screens and confirm they match word for word.",
        "Confirm on both ends, and confirm the grant appears on the Mac.",
        "Repeat once, deliberately confirming a mismatched phrase, and confirm pairing fails.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .ipChange,
      title: "Address change mid-session",
      proves: "A changed address does not silently carry a live session, and "
        + "recovery requires reauthentication rather than resuming counters.",
      procedure: [
        "Establish an authenticated session and observe a thread.",
        "Change the Mac's LAN address (renew the DHCP lease or switch networks).",
        "Confirm the phone loses the session rather than continuing against a stale endpoint.",
        "Confirm reconnection reauthenticates and does not resume the old counters.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .foregroundBackgroundReauth,
      title: "Background and foreground reauthentication",
      proves: "Backgrounding the app ends its session cleanly, and returning to "
        + "the foreground reauthenticates rather than reusing a suspended one.",
      procedure: [
        "Authenticate and observe a thread.",
        "Background the app and wait past the idle expiry.",
        "Foreground it and confirm a fresh authentication, not a resumed session.",
        "Confirm the observation resumes from the device's own cursor with no gap or replay.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .macRestart,
      title: "Mac restart",
      proves: "Grants, counters, and the anti-rollback sequence survive a host "
        + "restart, and LAN comes back off rather than re-enabling itself.",
      procedure: [
        "Pair, authenticate, and note the authority sequence the Mac reports.",
        "Restart the Mac and launch the bridge.",
        "Confirm LAN access is OFF and no record is advertised until the user enables it.",
        "Enable LAN, reconnect, and confirm the grant survived with its sequence not rolled back.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .keychainLockAndReboot,
      title: "Keychain lock and device reboot",
      proves: "A locked Keychain and a rebooted phone both fail closed rather "
        + "than degrading to an unauthenticated or cached path.",
      procedure: [
        "Authenticate, then reboot the iPhone and do not unlock it.",
        "Confirm the app cannot authenticate before first unlock.",
        "Unlock and confirm authentication succeeds without re-pairing.",
        "Lock the Mac's Keychain and confirm the bridge disables LAN rather than serving.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .tlsRotation,
      title: "Signed TLS rotation",
      proves: "A host-signed rotation statement moves the phone's pin exactly "
        + "once, and a replayed or rolled-back statement is refused.",
      procedure: [
        "Authenticate over the current pin.",
        "Rotate the Mac's TLS key and deliver the signed statement over the session.",
        "Confirm the phone accepts and reconnects against the new SPKI.",
        "Replay the same statement and confirm it is refused.",
        "Deliver a statement at a lower generation and confirm it is refused.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .filteredObserveAndReplay,
      title: "Filtered observation and replay",
      proves: "The phone sees only threads in its granted projects, and its "
        + "sequence namespace skips nothing it was entitled to see.",
      procedure: [
        "Grant the device one project of at least two on the Mac.",
        "Create activity in both projects.",
        "Confirm only the granted project's threads appear.",
        "Disconnect, create more activity in both, reconnect.",
        "Confirm replay resumes with no gap and still excludes the ungranted project.",
        "Force a retention gap and confirm the phone takes a filtered snapshot, not a partial replay.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .immediateRevocation,
      title: "Immediate revocation",
      proves: "Revoking a grant on the Mac takes effect on the live connection "
        + "at once, not at the next reconnect.",
      procedure: [
        "Authenticate and hold an open observation subscription.",
        "Revoke the device from the Mac while the connection is live.",
        "Confirm the connection closes with the revocation reason without the phone speaking first.",
        "Confirm reconnection is refused and the phone reports the device as revoked.",
      ],
      requiresLiveCodex: false
    ),
    AcceptanceCase(
      gate: .idempotentInterrupt,
      title: "Idempotent interrupt over Wi-Fi",
      proves: "An interrupt issued twice, or retried across a dropped "
        + "connection, executes exactly once.",
      procedure: [
        "Point the bridge at the fake app-server unless a live Codex is separately approved.",
        "Start a turn and issue an interrupt from the phone.",
        "Issue the identical command again and confirm the ledger replays rather than re-executing.",
        "Issue an interrupt, drop Wi-Fi before the result arrives, reconnect, and retry.",
        "Confirm exactly one interrupt reached the runtime.",
      ],
      requiresLiveCodex: false
    ),
  ]
}
