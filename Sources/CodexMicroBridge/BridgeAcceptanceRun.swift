import CompanionCrypto
import CompanionProtocol
import Crypto
import Foundation
import MacBridgeCore
import MacBridgeServer

/// Drives the Phase 2 acceptance path end to end from inside the signed app.
///
/// **Why this exists.** Everything below needs things only a signed, entitled,
/// provisioned bundle has: the Data Protection Keychain, the Secure Enclave,
/// and permission to publish a Bonjour record on macOS 15+. A unit test has
/// none of them, so the loopback end-to-end test can prove the protocol but
/// never the environment. This is the only place the two meet.
///
/// **On the enablement gate.** `ListenerEnablement.userRequested()` exists to
/// make every production enable greppable and to keep the listener off by
/// default across restarts — it is an audit and default-state control, not a
/// barrier against the operator of the machine. Running this harness *is* an
/// operator action: it requires setting an environment variable on a
/// development build, which nothing persists and no shipped configuration
/// sets. The bridge still comes up with LAN off, and the menu toggle is still
/// the only way a user turns it on.
///
/// The run tears down what it started, whatever happens.
public enum BridgeAcceptanceRun {
  /// Set to `1` to run the acceptance path at launch instead of idling.
  public static let environmentKey = "CODEX_MICRO_ACCEPTANCE_E2E"

  public static var isRequested: Bool {
    ProcessInfo.processInfo.environment[environmentKey] == "1"
  }

  /// Every step, in order, with its outcome. Written to standard error so a
  /// run is readable without a screenshot and diffable between attempts.
  static func report(_ step: String, _ detail: String = "") {
    let line = detail.isEmpty ? "acceptance: \(step)" : "acceptance: \(step) — \(detail)"
    FileHandle.standardError.write(Data((line + "\n").utf8))
  }

  /// Runs the whole path. Returns `true` only if a grant was stored.
  @discardableResult
  public static func run(_ live: BridgeLiveComposition) async -> Bool {
    report("start")

    // 0. Probe each prerequisite separately first. The controller collapses
    //    all of them onto startupDenied, which is right for a menu and useless
    //    for finding out which one refused.
    await preflight(live)

    // 1. Bind a real interface and publish a real Bonjour record. This is the
    //    step no test can reach: the strict interface policy refuses loopback,
    //    so the listener binds actual Wi-Fi or Ethernet or nothing.
    let endpoint: ListenerEndpoint
    do {
      endpoint = try await live.lanController.enable()
    } catch let failure as BridgeLANFailure {
      report("lan.failed", failure.rawValue)
      return false
    } catch {
      report("lan.failed", "unknown")
      return false
    }
    let advertising = await live.lanController.isAdvertising()
    report("lan.enabled", "port=\(endpoint.port) advertising=\(advertising)")
    // Bound to a local so teardown captures the controller rather than the
    // whole composition, which would cross an isolation boundary.
    let controller = live.lanController
    defer { Task { try? await controller.disable() } }

    guard advertising else {
      // Bind without publication is the failure Step 2.13 predicted for an
      // unbundled build. Reaching it from a signed one would mean the
      // entitlement or the allowlist is wrong, not the code.
      report("bonjour.notAdvertised", "listener bound but no record published")
      return false
    }

    // 2. Open a pairing session against the endpoint that is actually bound.
    let payload: PairingQRPayload
    do {
      payload = try await live.pairing.beginPairing(
        endpoint: endpoint,
        selection: try SecureProtocolSelection(major: 1, minor: 1, features: [.observeSync])
      )
    } catch {
      report("pairing.sessionFailed")
      return false
    }
    report("pairing.session", "qr=\(BridgePairingQR.text(for: payload).count) chars")

    // 3. Act as the phone: scan the QR, pin the SPKI it named, and speak the
    //    real handshake over the real LAN address. The whole handshake runs on
    //    one connection because the host binds an in-flight pairing to the
    //    connection it arrived on.
    let deviceKey = P256.Signing.PrivateKey()
    let deviceID = UUID()
    let device: PairingDeviceEndpoint
    let attempt: PairingDeviceAttempt
    do {
      guard let scanned = BridgePairingQR.payload(fromScanned: BridgePairingQR.text(for: payload))
      else {
        report("pairing.qrUndecodable")
        return false
      }
      device = PairingDeviceEndpoint(
        identity: try PairingDeviceIdentity(
          deviceID: deviceID,
          publicKeyX963: deviceKey.publicKey.x963Representation,
          signer: AcceptanceDeviceSigner(key: deviceKey)
        ))
      attempt = try device.beginPairing(with: scanned)
    } catch {
      report("pairing.deviceSetupFailed")
      return false
    }

    let client = PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: endpoint.spkiFingerprint, deadline: .seconds(15))
    guard let url = PinnedProbeWebSocketClient.url(for: endpoint) else {
      report("pairing.badURL")
      return false
    }
    report("pairing.connecting", "host=\(endpoint.host)")

    do {
      try await client.withConnection(url: url) { connection in
        let request = try ListenerHandshakeEnvelope(
          kind: .pairingRequest, payload: try JSONEncoder().encode(attempt.request))
        try await connection.send(try request.encoded())
        let reply = try ListenerHandshakeEnvelope.decode(try await connection.receive())
        guard reply.kind == .pairingResponse else {
          report("pairing.unexpectedReply", reply.kind.rawValue)
          throw AcceptanceFailure.refused
        }
        report("tls.pinned", "real TLS 1.3 over LAN, SPKI matched")

        let response = try JSONDecoder().decode(
          SecurePairingResponse.self, from: reply.payload)
        let verification = try attempt.verifyHostResponse(response)

        // 4. Both endpoints must show the same six words. This is the property
        //    the phrase exists for, and the only defence against something else
        //    on this network answering.
        let model = live.pairingModel
        let onScreen = await MainActor.run { model.pendingWords }
        let devicePhrase = verification.verificationPhrase.displayWords
        guard onScreen == devicePhrase, onScreen.count == 6 else {
          report("phrase.mismatch", "mac=\(onScreen.count) device=\(devicePhrase.count)")
          throw AcceptanceFailure.phraseMismatch
        }
        report("phrase.matched", devicePhrase.joined(separator: " "))

        // 5. Both sides confirm.
        await live.pairing.confirmDisplayedPhrase()
        let confirmation = try verification.confirmLocally(
          matching: verification.verificationPhrase)
        try await connection.send(
          try ListenerHandshakeEnvelope(
            kind: .pairingConfirmation, payload: try JSONEncoder().encode(confirmation)
          ).encoded())
        report("pairing.confirmed")
      }
    } catch {
      report("pairing.exchangeFailed", "\(error)")
      return false
    }

    // 6. The Mac must hold a grant. Without it the device would reconnect and
    //    be refused as unknown, which is the failure this whole step exists to
    //    rule out.
    for _ in 0..<40 {
      if let grant = try? await live.authority.authoritativeGrant(deviceID: deviceID) {
        report(
          "grant.stored",
          "capabilities=\(grant.capabilities.map(\.rawValue).sorted().joined(separator: ","))"
            + " projects=\(grant.permittedProjectIDs.count)"
            + " ceiling=\(grant.actionProfileCeiling.rawValue)")
        report("PASS", "paired over real Wi-Fi and the grant is stored")
        return true
      }
      try? await Task.sleep(for: .milliseconds(50))
    }
    report("grant.missing", "pairing completed but no grant was written")
    return false
  }
}

extension BridgeAcceptanceRun {
  /// Runs each startup prerequisite on its own and reports the result.
  static func preflight(_ live: BridgeLiveComposition) async {
    do {
      let binding = try ListenerInterfaceDiscovery.firstEligibleBinding(
        policy: ListenerInterfacePolicy())
      report(
        "preflight.interface.ok",
        "\(binding.interface.identifier) kind=\(binding.interface.kind.rawValue)")
    } catch {
      report("preflight.interface.failed", "\(error)")
    }

    do {
      try await live.assembly.codexProbe.assertCodexSupported()
      report("preflight.codex.ok")
    } catch {
      report("preflight.codex.failed", "\(error)")
    }

    do {
      try await live.assembly.policyProbe.assertPolicyAvailable()
      report("preflight.policy.ok")
    } catch {
      report("preflight.policy.failed", "\(error)")
    }

    do {
      try await live.assembly.grantProbe.assertGrantAuthorityAvailable()
      report("preflight.grantAuthority.ok")
    } catch {
      report("preflight.grantAuthority.failed", "\(error)")
    }

    do {
      let identity = try await live.assembly.tls.servingIdentity()
      report("preflight.tlsIdentity.ok", "spki=\(identity.spkiFingerprint.count) bytes")
    } catch {
      report("preflight.tlsIdentity.failed", "\(error)")
    }
  }
}

private enum AcceptanceFailure: Error {
  case refused
  case phraseMismatch
}

/// Stands in for the phone's Secure Enclave signer. The Mac has no second
/// Enclave identity to spend on this, and the property under test is the
/// transport and the choreography, not the device's key storage — which the
/// acceptance host proves separately on real hardware.
private struct AcceptanceDeviceSigner: PairingTranscriptSigner {
  let key: P256.Signing.PrivateKey

  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try key.signature(for: canonicalBytes).rawRepresentation
  }
}
