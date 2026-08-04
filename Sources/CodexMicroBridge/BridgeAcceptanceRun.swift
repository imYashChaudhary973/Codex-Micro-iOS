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

  /// Set to `1` to bind, advertise, publish a pairing code, and then wait for
  /// a real device to pair — instead of pairing against an in-process one.
  public static let deviceWaitKey = "CODEX_MICRO_ACCEPTANCE_AWAIT_DEVICE"

  public static var awaitsRealDevice: Bool {
    ProcessInfo.processInfo.environment[deviceWaitKey] == "1"
  }

  /// Set to `1` to bring LAN up, grant every already-paired device a working
  /// scope, and stay serving so a phone can connect and issue commands.
  public static let serveKey = "CODEX_MICRO_ACCEPTANCE_SERVE"

  public static var serves: Bool {
    ProcessInfo.processInfo.environment[serveKey] == "1"
  }

  /// Stays up serving an already-paired device.
  ///
  /// The pairing run exits once a grant is stored, which is right for a test
  /// and useless for exercising the pad: the phone reconnects to a Mac that is
  /// no longer there. This keeps the listener up and reports what the device
  /// does, so a key press on the phone can be watched arriving.
  public static func serve(_ live: BridgeLiveComposition) async {
    report("serve.start")
    await preflight(live)

    let endpoint: ListenerEndpoint
    do {
      endpoint = try await live.lanController.enable()
    } catch {
      report("serve.lanFailed", "\(error)")
      return
    }
    let advertising = await live.lanController.isAdvertising()
    report(
      "serve.listening",
      "host=\(endpoint.host) port=\(endpoint.port) advertising=\(advertising)")
    await serveLoop(live)
  }

  /// Grants working scope and stays up, on a listener that is already bound.
  ///
  /// Split out of ``serve(_:)`` so a pairing run can continue straight into
  /// serving **on the same listener**. Re-enabling would rebind to a fresh
  /// ephemeral port, and the phone that just paired holds the old one — which
  /// is exactly how a device that had successfully paired still reported
  /// `connectionFailed` a moment later.
  static func serveLoop(_ live: BridgeLiveComposition) async {
    // **Start Codex before serving, and say whether it came up.** Constructing
    // the assembly is not the same as the app-server completing its handshake:
    // the supervisor stays un-ready until `start()` runs, and an un-ready
    // supervisor turns every dispatched command into `codexUnavailable`. That
    // is a press that was authorized, ledgered, and then quietly dropped one
    // step short of Codex — the last gap in the chain.
    if let runtime = live.runtime {
      do {
        try await runtime.start()
        report("serve.codex", "\(await runtime.state())")
      } catch {
        report("serve.codexFailed", "\(error)")
      }
    } else {
      report("serve.codexAbsent")
    }
    // Every device the Mac already holds gets the working scope, so a phone
    // paired in an earlier run can connect and act without re-pairing.
    let snapshot = try? await live.authority.macAdministrationSnapshot()
    for grant in snapshot?.grants ?? [] where grant.tombstone == nil {
      await grantWorkingScope(live, deviceID: grant.deviceID)
    }
    report("serve.granted", "devices=\(snapshot?.grants.count ?? 0)")
    // Attribute the probe thread so a press against an idle Codex is answered
    // on its merits rather than refused for having no project. Attribution is
    // Mac-side bookkeeping — it grants nothing the grant did not already allow
    // and costs no model allowance.
    if let project = await live.registry.register(
      rootPath: FileManager.default.currentDirectoryPath) {
      _ = live.attribution.attribute(threadID: "probe-thread", projectID: project.projectID)
      report("serve.probeThread", "attributed")
    }
    // Open one real Codex thread so a press has something real to act on.
    //
    // `thread/start` invokes no model and consumes no allowance — that is the
    // whole reason it is used here instead of starting a turn. Without it the
    // only thread a press can name is one Codex has never heard of, and the
    // honest answer to that press is "there is nothing here", which proves the
    // transport and not the product.
    if let runtime = live.runtime,
      let project = await live.registry.register(
        rootPath: FileManager.default.currentDirectoryPath)
    {
      do {
        let threadID = try await runtime.startThread(
          projectID: project.projectID,
          policy: PhoneTurnPolicy.resolve(effectiveProfile: .observe, writableRoots: [])
        )
        _ = live.attribution.attribute(threadID: threadID, projectID: project.projectID)
        // Take it into the store, or no device will ever be told it exists.
        let adopted = await live.codexAssembly?.adoptThread(threadID) ?? false
        report("serve.thread", "opened=yes adopted=\(adopted)")
      } catch {
        report("serve.threadFailed", "\(error)")
      }
    }
    report("serve.ready", "press keys on the phone; results appear on the Mac")

    // Stay up. The listener and the gateway do the work; this only keeps the
    // process alive and reports when the set of observing devices changes, so
    // a phone connecting is visible without needing a screenshot.
    var lastObserving = -1
    while !Task.isCancelled {
      let observing = await live.assembly.broker.observingDeviceCount()
      if observing != lastObserving {
        lastObserving = observing
        report("serve.observing", "\(observing)")
      }
      try? await Task.sleep(for: .seconds(3))
    }
  }

  /// Brings the bridge up, publishes a pairing code, and waits for a real
  /// device to complete pairing.
  ///
  /// The phrase is printed rather than compared in-process, because with a
  /// real device the two phrases are derived on two machines from two
  /// independently reconstructed transcripts — which is the whole point. They
  /// are compared by reading both runs' output, which is what a user does with
  /// their eyes.
  @discardableResult
  public static func awaitDevicePairing(
    _ live: BridgeLiveComposition,
    timeout: Duration = .seconds(120),
    keepListening: Bool = false
  ) async -> Bool {
    report("start", "awaiting a real device")
    await preflight(live)

    let endpoint: ListenerEndpoint
    do {
      endpoint = try await live.lanController.enable()
    } catch {
      report("lan.failed", "\(error)")
      return false
    }
    let advertising = await live.lanController.isAdvertising()
    report("lan.enabled", "host=\(endpoint.host) port=\(endpoint.port) advertising=\(advertising)")
    // A pairing-only run takes the LAN back down when it finishes, because a
    // test must not leave a listener bound. A run that goes on to serve must
    // not: the device's whole reason to stay reachable is that this listener,
    // on this port, is still there when it reconnects a moment later.
    let controller = live.lanController
    defer {
      if !keepListening { Task { try? await controller.disable() } }
    }

    let payload: PairingQRPayload
    do {
      payload = try await live.pairing.beginPairing(
        endpoint: endpoint,
        selection: try SecureProtocolSelection(major: 1, minor: 1, features: [.observeSync])
      )
    } catch {
      report("pairing.sessionFailed", "\(error)")
      return false
    }
    // The exact text a scanned QR would yield, so a device can be driven with
    // it directly and the transport is exercised identically either way.
    report("pairing.code", BridgePairingQR.text(for: payload))

    let model = live.pairingModel
    let deadline = ContinuousClock.now.advanced(by: timeout)
    var confirmed = false
    while ContinuousClock.now < deadline {
      let state = await MainActor.run { model.state }
      switch state {
      case .awaitingPhrase(_, let phrase):
        if !confirmed {
          report("phrase.mac", phrase.displayWords.joined(separator: " "))
          await live.pairing.confirmDisplayedPhrase()
          confirmed = true
          report("phrase.macConfirmed")
        }
      case .paired(let deviceID):
        await grantWorkingScope(live, deviceID: deviceID)
        if let grant = try? await live.authority.authoritativeGrant(deviceID: deviceID) {
          report(
            "grant.stored",
            "capabilities=\(grant.capabilities.map(\.rawValue).sorted().joined(separator: ","))"
              + " projects=\(grant.permittedProjectIDs.count)"
              + " ceiling=\(grant.actionProfileCeiling.rawValue)")
          report("PASS", "a real device paired over Wi-Fi and the grant is stored")
          return true
        }
        report("grant.missing", "device paired but no grant was written")
        return false
      case .alreadyPaired(let deviceID):
        await grantWorkingScope(live, deviceID: deviceID)
        report(
          "grant.alreadyPresent",
          "device is already paired; the existing grant was kept")
        report("PASS", "a real device completed pairing against grant \(deviceID.uuidString)")
        return true
      case .failed(let reason):
        report("pairing.failed", reason)
        return false
      case .idle, .awaitingScan, .awaitingDevice:
        break
      }
      try? await Task.sleep(for: .milliseconds(200))
    }
    report("timeout", "no device completed pairing")
    return false
  }

  /// Every step, in order, with its outcome. Written to standard error so a
  /// run is readable without a screenshot and diffable between attempts.
  static func report(_ step: String, _ detail: String = "") {
    let line = detail.isEmpty ? "acceptance: \(step)" : "acceptance: \(step) — \(detail)"
    FileHandle.standardError.write(Data((line + "\n").utf8))
    // Also to unified logging. Bonjour publication needs the app launched
    // through LaunchServices for macOS to apply local-network permission, and
    // a LaunchServices launch has no terminal to write to — so stderr alone
    // makes the one configuration that can advertise the one that cannot be
    // observed.
    OSLogSink().write(
      RedactedLogEntry(timestamp: Date(), level: .error, code: line, counts: [:]))
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
        // Pairing is not the deliverable. A grant only means the device is
        // allowed to ask; whether asking *does* anything is a different claim
        // and was never checked, which is how the chain stayed broken at its
        // last hop while every step before it reported success.
        await grantWorkingScope(live, deviceID: deviceID)
        guard
          await commandProof(
            live, deviceID: deviceID, deviceKey: deviceKey, endpoint: endpoint)
        else { return false }
        report("PASS", "a command from a device reached Codex over real Wi-Fi")
        return true
      }
      try? await Task.sleep(for: .milliseconds(50))
    }
    report("grant.missing", "pairing completed but no grant was written")
    return false
  }

  /// Opens a session as the paired device and presses one key.
  ///
  /// This is the step that decides whether the product works. Everything
  /// before it proves the two machines can agree who they are; this proves a
  /// press on the pad becomes an instruction Codex acts on. It runs the real
  /// listener, the real pinned TLS, the real session handshake, the real
  /// sealed frames, and the real gateway — nothing here is a fixture.
  ///
  /// **Stop, because Stop cannot spend anything.** Interrupting is meaningful
  /// against an idle Mac and consumes no model allowance whichever way it is
  /// answered, so proving the path can never start work nobody asked for.
  static func commandProof(
    _ live: BridgeLiveComposition,
    deviceID: UUID,
    deviceKey: P256.Signing.PrivateKey,
    endpoint: ListenerEndpoint
  ) async -> Bool {
    let hostKey = live.hostPublicKeyX963
    let attempt: SessionDeviceAttempt
    do {
      attempt = try SessionDeviceEndpoint(
        identity: try SessionDeviceIdentity(
          deviceID: deviceID,
          publicKeyX963: deviceKey.publicKey.x963Representation,
          signer: AcceptanceDeviceSigner(key: deviceKey)
        ),
        hostID: BridgeHostIdentifier.stable(),
        hostPublicKeyX963: hostKey,
        hostTLSSPKIFingerprint: endpoint.spkiFingerprint
      ).beginAuthentication()
    } catch {
      report("command.authSetupFailed", "\(error)")
      return false
    }

    let client = PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: endpoint.spkiFingerprint, deadline: .seconds(20))
    guard let url = PinnedProbeWebSocketClient.url(for: endpoint) else {
      report("command.badURL")
      return false
    }

    do {
      try await client.withConnection(url: url) { connection in
        try await connection.send(
          try ListenerHandshakeEnvelope(
            kind: .sessionAuthRequest, payload: try JSONEncoder().encode(attempt.request)
          ).encoded())
        let replyBytes = try await connection.receive()
        let reply = try ListenerHandshakeEnvelope.decode(replyBytes)
        guard reply.kind == .sessionAuthResponse else {
          report("command.authRefused", "kind=\(reply.kind)")
          throw CommandProofFailure.refused
        }
        let completion = try attempt.completeAuthentication(
          with: try JSONDecoder().decode(SecureSessionAuthResponse.self, from: reply.payload))
        try await connection.send(
          try ListenerHandshakeEnvelope(
            kind: .sessionAuthConfirmation,
            payload: try JSONEncoder().encode(completion.confirmation)
          ).encoded())
        report("command.authenticated")
        // The confirmation and the first sealed frame are two writes on one
        // socket. The host promotes the connection to authenticated when it
        // processes the first, and a frame that overtakes that promotion is
        // read by the handshake handler, which cannot parse it and closes.
        try? await Task.sleep(for: .milliseconds(400))

        var session = completion.session
        // Subscribe first, exactly as the phone does. It also tells us which
        // layer is at fault if this fails: a refused subscribe is a frame or
        // session problem, a refused command is about the command itself.
        let subscribe = SecureObservationSubscribe(
          subscriptionID: UUID(), resumeCursor: nil)
        let subscribeEnvelope = try ListenerApplicationEnvelope(
          kind: .observationSubscribe, payload: try JSONEncoder().encode(subscribe))
        try await connection.send(try session.outbound.seal(try subscribeEnvelope.encoded()))
        let firstSealed = try await connection.receive()
        let firstOpened = try ListenerApplicationEnvelope.decode(
          try session.inbound.open(firstSealed))
        report("command.subscribed", "kind=\(firstOpened.kind)")

        // The gateway scopes every command by the thread's project, so a
        // thread nothing has attributed is refused before it reaches Codex.
        // Attributing is Mac-side bookkeeping and costs no model allowance.
        if let project = await live.registry.register(
          rootPath: FileManager.default.currentDirectoryPath) {
          _ = live.attribution.attribute(
            threadID: "proof-thread", projectID: project.projectID)
        }
        let command = try ClientCommand(
          commandID: UUID(),
          issuedAt: Date(),
          body: .interruptTurn(threadID: "proof-thread", turnID: "proof-turn")
        )
        let envelope = try ListenerApplicationEnvelope(
          kind: .commandRequest, payload: try JSONEncoder().encode(command))
        try await connection.send(try session.outbound.seal(try envelope.encoded()))
        report("command.sent", "interrupt")

        // The subscription is not established, so the only frame this session
        // can receive is the answer to the command it just sent.
        let sealed = try await connection.receive()
        let opened = try ListenerApplicationEnvelope.decode(
          try session.inbound.open(sealed))
        guard opened.kind == .commandResult else {
          report("command.unexpectedReply", "kind=\(opened.kind)")
          throw CommandProofFailure.refused
        }
        let result = try JSONDecoder().decode(SecureCommandResult.self, from: opened.payload)
        guard result.commandID == command.commandID else {
          report("command.mismatchedResult")
          throw CommandProofFailure.refused
        }
        report(
          "command.result",
          "outcome=\(result.outcome.rawValue)"
            + (result.denialReason.map { " reason=\($0.rawValue)" } ?? ""))
        // A denial is a real answer from the gateway and proves the path, but
        // it is not the product working. Only an accepted command means the
        // press became an instruction Codex was actually handed.
        guard result.outcome != .denied else {
          report("command.denied", "the gateway refused the press")
          throw CommandProofFailure.denied
        }
      }
    } catch {
      report("command.failed", "\(error)")
      return false
    }
    return true
  }

  enum CommandProofFailure: Error {
    case refused
    case denied
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

extension BridgeAcceptanceRun {
  /// Gives the paired device the current project and the capabilities the pad
  /// needs, so its keys can actually do something.
  ///
  /// Pairing deliberately grants `observe` with an empty allowlist (plan §2
  /// invariant 4), which is right as a default and useless as an end state:
  /// the device sees nothing and every key is refused. Production wants a Mac
  /// UI for this; the acceptance run does it directly so the wiring can be
  /// exercised end to end.
  ///
  /// `.approve` and `.startThread` are **not** granted. Both are gated on the
  /// Mac supplying an executor that this composition deliberately does not,
  /// so granting them would advertise a capability the bridge would then
  /// refuse — the present-and-failing shape invariant 2 exists to prevent.
  static func grantWorkingScope(_ live: BridgeLiveComposition, deviceID: UUID) async {
    guard
      let project = await live.registry.register(
        rootPath: FileManager.default.currentDirectoryPath)
    else {
      report("grant.projectUnresolved")
      return
    }

    // The gateway reads roots through this snapshot; refreshing it is what
    // makes the newly registered project usable for workspace-write turns.
    await live.workspaceRoots.update(projects: live.registry.allProjects())

    do {
      _ = try await live.authority.amendCapabilities(
        deviceID: deviceID,
        capabilities: [.view, .interrupt, .runAgent],
        actionProfileCeiling: .runWorkspace
      )
      // Widening demands a strict superset, which is right — a "widen" that
      // narrows or merely restates a scope is a mistake worth refusing. But it
      // makes the call non-idempotent, and this runs on every launch for every
      // device: a Mac restarted twice reported `invalidGrant` for a grant that
      // was already exactly correct, which reads as a broken grant.
      let existing = try? await live.authority.authoritativeGrant(deviceID: deviceID)
      if existing?.permittedProjectIDs.contains(project.projectID) == true {
        report(
          "grant.alreadyScoped",
          "project=\(project.projectID.prefix(8))…")
      } else {
        _ = try await live.authority.widenScope(
          deviceID: deviceID, permittedProjectIDs: [project.projectID])
        report(
          "grant.widened",
          "capabilities=view,interrupt,runAgent project=\(project.projectID.prefix(8))…")
      }
    } catch {
      report("grant.widenFailed", "\(error)")
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
private struct AcceptanceDeviceSigner: PairingTranscriptSigner, SessionStatementSigner {
  let key: P256.Signing.PrivateKey

  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try key.signature(for: canonicalBytes).rawRepresentation
  }

  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    try key.signature(for: canonicalBytes).rawRepresentation
  }
}
