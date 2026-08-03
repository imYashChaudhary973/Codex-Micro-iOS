import CodexAppServer
import CompanionCrypto
import CompanionProtocol
import Crypto
import Foundation
import MacBridgeCore
import MacBridgeServer
import XCTest

@testable import CodexMicroBridge

/// The composition root: what the shipping app actually wires together.
///
/// These tests exist because every other suite proves a component against a
/// seam, and a seam proves nothing about whether anyone connected it.
final class BridgeNetworkAssemblyTests: XCTestCase {

  // MARK: - The wiring defect this step closes

  /// Before Step 2.14, `HardenedWSSListener.makeBootstrap` called
  /// `configureChild` without an observation, command, or frame argument, so
  /// every production listener took the *denying* defaults. The Step 2.8 and
  /// 2.9 handlers were reachable only by calling `ListenerPipeline` directly,
  /// which only tests did.
  ///
  /// This test could not have been written against that code — there were no
  /// `observation`, `commands`, or `frameProvider` fields on
  /// `ListenerConfiguration` to inject or assert. That is what made the gap
  /// invisible: not a failing assertion, but an absent one.
  func testTheAssembledConfigurationCarriesRealHandlersNotDenyingOnes() async throws {
    let world = try await World()

    let configuration = world.assembly.makeConfiguration(
      enablement: .userRequested(),
      binding: try ListenerInterfaceBinding.testOnlyLoopback(),
      interfacePolicy: ListenerInterfacePolicy(allowLoopbackForTests: true)
    )

    XCTAssertTrue(configuration.isEnabled)
    XCTAssertTrue(
      configuration.observation is BrokerObservationHandler,
      "observation fell back to the denying handler")
    XCTAssertTrue(
      configuration.commands is GatewayCommandHandler,
      "commands fell back to the denying handler")
    XCTAssertFalse(
      configuration.frameProvider is DenyingListenerSessionFrameProvider,
      "an authenticated connection would be able to open nothing")
  }

  /// The frame registry the handshake writes into must be the *same object*
  /// the connection reads from. Two registries would authenticate a device
  /// and then leave it unable to open a single application message — a
  /// failure that only shows up against a real phone.
  func testTheHandshakeAndTheConnectionShareOneFrameRegistry() async throws {
    let world = try await World()

    let configuration = world.assembly.makeConfiguration(
      enablement: .userRequested(),
      binding: try ListenerInterfaceBinding.testOnlyLoopback(),
      interfacePolicy: ListenerInterfacePolicy(allowLoopbackForTests: true)
    )

    let handshake = try XCTUnwrap(
      configuration.handshake as? CoordinatorListenerHandshakeHandler)
    let provider = try XCTUnwrap(
      configuration.frameProvider as? ListenerSessionFrameRegistry)
    XCTAssertTrue(handshake.frameRegistry === provider)
  }

  /// Each enable builds a fresh listener, and a fresh listener must get a
  /// fresh registry: directional codecs minted under a previous LAN session
  /// carry counters, and a resumed counter is a replay window.
  func testEachListenerGetsItsOwnFrameRegistry() async throws {
    let world = try await World()
    let binding = try ListenerInterfaceBinding.testOnlyLoopback()
    let policy = ListenerInterfacePolicy(allowLoopbackForTests: true)

    let first = world.assembly.makeConfiguration(
      enablement: .userRequested(), binding: binding, interfacePolicy: policy)
    let second = world.assembly.makeConfiguration(
      enablement: .userRequested(), binding: binding, interfacePolicy: policy)

    let firstRegistry = try XCTUnwrap(first.frameProvider as? ListenerSessionFrameRegistry)
    let secondRegistry = try XCTUnwrap(second.frameProvider as? ListenerSessionFrameRegistry)
    XCTAssertFalse(firstRegistry === secondRegistry)
  }

  // MARK: - Off by default

  /// The disabled configuration must deny on every seam, not only refuse to
  /// bind. A configuration is a value; nothing stops one being handed to a
  /// pipeline directly.
  func testTheDisabledConfigurationDeniesEverySeam() throws {
    let configuration = ListenerConfiguration.disabled(
      binding: try ListenerInterfaceBinding.testOnlyLoopback())

    XCTAssertFalse(configuration.isEnabled)
    XCTAssertTrue(configuration.handshake is DenyingListenerHandshakeHandler)
    XCTAssertTrue(configuration.observation is DenyingListenerObservationHandler)
    XCTAssertTrue(configuration.commands is DenyingListenerCommandHandler)
    XCTAssertTrue(configuration.frameProvider is DenyingListenerSessionFrameProvider)
  }

  /// A bridge whose LAN was never toggled binds nothing, even with every
  /// other prerequisite satisfied. This runs a real listener's `start()`; it
  /// refuses before reaching a socket.
  func testADisabledListenerRefusesToBind() async throws {
    let world = try await World()
    let listener = HardenedWSSListener(
      configuration: .disabled(binding: try ListenerInterfaceBinding.testOnlyLoopback()),
      prerequisites: world.assembly.makePrerequisites()
    )

    do {
      _ = try await listener.start()
      XCTFail("a disabled listener bound a socket")
    } catch let error as ListenerError {
      XCTAssertEqual(error, .startupDenied(.notEnabled))
    }
  }

  /// Production defaults to the strict interface policy: loopback is not a
  /// LAN, so a bridge binds a real interface or nothing.
  func testTheProductionFactoryRefusesLoopbackByDefault() throws {
    let configuration = ListenerConfiguration.enabled(
      by: .userRequested(),
      binding: try ListenerInterfaceBinding.testOnlyLoopback(),
      handshake: DenyingListenerHandshakeHandler()
    )

    XCTAssertFalse(
      configuration.interfacePolicy.allows(
        ListenerInterface(
          identifier: "lo0", kind: .loopback, isUp: true, isRunning: true,
          isPointToPoint: false)))
  }

  // MARK: - Startup probes

  func testTheGrantProbePassesWhenTheAuthorityIsAvailable() async throws {
    let world = try await World()
    try await world.assembly.grantProbe.assertGrantAuthorityAvailable()
  }

  /// A latched authority must take LAN down with it rather than let the
  /// listener bind into a state where every authorization read fails.
  func testTheGrantProbeRefusesWhenTheAuthorityIsLatchedClosed() async throws {
    let storage = InMemoryGrantAuthorityStore()
    storage.failLoads(with: .authorityMissing)
    let authority = DeviceGrantAuthority(storage: storage, clock: { 1_000_000 })
    let probe = BridgeGrantAuthorityProbe(authority: authority)

    do {
      try await probe.assertGrantAuthorityAvailable()
      XCTFail("a latched authority passed the probe")
    } catch {
      // Any throw disables LAN; the closed reason belongs to the authority.
    }
  }

  /// The floor of the profile lattice is what `authorize` leans on to refuse
  /// agent work. If a later profile moved it, every device widens at once.
  func testThePolicyProbeConfirmsTheLatticeFloorIsObserve() async throws {
    try await BridgeCapabilityPolicyProbe().assertPolicyAvailable()

    XCTAssertEqual(
      MobileActionProfile.mostRestrictive(MobileActionProfile.allCases), .observe)
  }

  func testTheCodexProbePassesForASupportedBuild() async throws {
    let manifest = CodexCompatibilityManifest(codexVersion: "1.2.3", schemaDigest: "abc")
    let probe = BridgeCodexSupportProbe(
      probe: StubCompatibilityProbe(
        report: CodexCompatibilityReport(codexVersion: "1.2.3", schemaDigest: "abc")),
      policy: CodexCompatibilityPolicy(supportedManifests: [manifest])
    )

    try await probe.assertCodexSupported()
  }

  /// Unsupported Codex disables LAN outright; it is not a degraded mode.
  func testTheCodexProbeRefusesAnUnsupportedVersionAndASchemaMismatch() async throws {
    let manifest = CodexCompatibilityManifest(codexVersion: "1.2.3", schemaDigest: "abc")
    let policy = CodexCompatibilityPolicy(supportedManifests: [manifest])

    for report in [
      CodexCompatibilityReport(codexVersion: "9.9.9", schemaDigest: "abc"),
      CodexCompatibilityReport(codexVersion: "1.2.3", schemaDigest: "different"),
    ] {
      let probe = BridgeCodexSupportProbe(
        probe: StubCompatibilityProbe(report: report), policy: policy)
      do {
        try await probe.assertCodexSupported()
        XCTFail("unsupported Codex passed: \(report)")
      } catch let failure as BridgeCodexSupportProbe.Failure {
        XCTAssertNotEqual(failure, .unsupported(.supported))
      }
    }
  }

  /// A probe that cannot run at all is not a pass.
  func testTheCodexProbeRefusesWhenTheProbeItselfFails() async throws {
    let probe = BridgeCodexSupportProbe(
      probe: StubCompatibilityProbe(report: nil),
      policy: CodexCompatibilityPolicy(supportedManifests: [])
    )

    do {
      try await probe.assertCodexSupported()
      XCTFail("a failed probe passed")
    } catch {}
  }

  // MARK: - No eligible interface

  /// "No Wi-Fi or Ethernet is eligible" must land on the same closed
  /// `startupDenied` the menu already shows, not a separate crash path.
  func testAnUnresolvableInterfaceBecomesStartupDenied() async throws {
    let controller = BridgeLANController(
      makeListener: { UnavailableBridgeListener() },
      bonjour: ListenerBonjourCoordinator(publisher: DisabledListenerBonjourPublisher())
    )

    do {
      _ = try await controller.enable()
      XCTFail("enabled with no eligible interface")
    } catch let failure as BridgeLANFailure {
      XCTAssertEqual(failure, .startupDenied)
    }
    let state = await controller.currentState()
    XCTAssertEqual(state, .failed(.startupDenied))
    let advertising = await controller.isAdvertising()
    XCTAssertFalse(advertising, "advertised with nothing bound")
  }

  // MARK: - Fixture

  /// The whole graph, wired the way the app wires it, over deterministic
  /// backing stores.
  private struct World {
    let assembly: BridgeNetworkAssembly

    init() async throws {
      let storage = InMemoryGrantAuthorityStore()
      let authority = DeviceGrantAuthority(storage: storage, clock: { 1_000_000 })
      _ = try await authority.addGrant(
        deviceID: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        capabilities: [.view, .interrupt],
        permittedProjectIDs: ["project-a"]
      )

      let table = ThreadProjectTable()
      let sessions = try SessionCoordinator(
        hostID: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
        hostTLSSPKIFingerprint: Data(repeating: 0x77, count: 32),
        authority: GrantAuthoritySessionAuthority(authority: authority, clock: { 1_000_000 }),
        signer: AssemblyRefusingSigner(),
        store: InMemoryAuthenticatedSessionStore()
      )
      let broker = DeviceObservationBroker(
        scopes: authority,
        snapshots: AssemblyEmptySnapshotSource(),
        attribution: table,
        journalEpoch: try SystemJournalEpochMint().mintJournalEpoch()
      )
      let gateway = NetworkCommandGateway(
        authority: authority,
        attribution: table,
        ledger: InMemoryCommandLedger(),
        sessions: SessionCoordinatorVerifier(coordinator: sessions),
        runtime: AssemblyReadyRuntime(),
        responder: AssemblyRefusingResponder(),
        turnStarter: AssemblyRefusingTurnStarter(),
        turnSteerer: AssemblyRefusingTurnSteerer(),
        readCursors: try DeviceReadCursorStore(
          storage: InMemoryReadCursorStorage(),
          scopes: authority,
          attribution: table,
          clock: { 1_000_000 }
        )
      )

      assembly = BridgeNetworkAssembly(
        authority: authority,
        sessions: sessions,
        pairing: nil,
        broker: broker,
        gateway: gateway,
        tls: BridgeSecureEnclaveTLSProvider(makeStore: {
          BridgeIdentityStore(backend: UnavailableIdentityBackend(), resetPolicy: { false })
        }),
        codexProbe: BridgeCodexSupportProbe(
          probe: StubCompatibilityProbe(
            report: CodexCompatibilityReport(codexVersion: "1.2.3", schemaDigest: "abc")),
          policy: CodexCompatibilityPolicy(
            supportedManifests: [
              CodexCompatibilityManifest(codexVersion: "1.2.3", schemaDigest: "abc")
            ])
        )
      )
    }
  }
}

// MARK: - Deterministic doubles

/// Returns a fixed report, or throws when built with none.
private struct StubCompatibilityProbe: CodexCompatibilityProbing {
  let report: CodexCompatibilityReport?

  func probe() async throws -> CodexCompatibilityReport {
    guard let report else { throw CodexCompatibilityProbeError.commandFailed }
    return report
  }
}

private struct AssemblyRefusingSigner: SessionStatementSigner {
  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    throw SessionClosedReason.deviceSignatureUnavailable
  }
}

private struct AssemblyEmptySnapshotSource: ObservationSnapshotProviding {
  func currentObservationSnapshot() async -> CompanionStateSnapshot {
    CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000_000), latestSequence: 0, threads: [])
  }
}

private struct AssemblyReadyRuntime: NetworkRuntimeReadiness {
  func isReadyForStateChange() async -> Bool { true }
}

private struct AssemblyRefusingResponder: CodexApprovalResponding {
  func respondToServerRequest(id: Int64, result: JSONValue) async throws {
    throw CodexRuntimeRequestError.notReady
  }

  func interruptTurn(threadID: String, turnID: String) async throws {
    throw CodexRuntimeRequestError.notReady
  }
}

private struct AssemblyRefusingTurnStarter: CodexTurnStarting {
  func startTurn(threadID: String, prompt: String, policy: PhoneTurnPolicy) async throws -> String {
    throw CodexRuntimeRequestError.notReady
  }
}

private struct AssemblyRefusingTurnSteerer: CodexTurnSteering {
  func steerTurn(threadID: String, turnID: String, prompt: String) async throws {
    throw CodexRuntimeRequestError.notReady
  }
}

/// An identity backend that stores nothing and creates nothing.
///
/// None of these tests calls `servingIdentity()` — a Secure Enclave key needs
/// an entitled signed host, which is exactly what Step 2.14's acceptance run
/// provides and a unit test cannot. The backend exists so the assembly can be
/// constructed; a test that reached it would fail loudly rather than quietly
/// succeed against a fake key.
private final class UnavailableIdentityBackend: SecureIdentityBackend {
  func insertClaim(for role: BridgeIdentityRole) throws -> BridgeClaimInsertion {
    throw BridgeIdentityError.identityMissing
  }

  func claimCount(for role: BridgeIdentityRole) throws -> Int { 0 }

  func removeClaim(for role: BridgeIdentityRole) throws {}

  func createKey(for role: BridgeIdentityRole) throws -> any SecureIdentityKey {
    throw BridgeIdentityError.identityMissing
  }

  func existingKeys(for role: BridgeIdentityRole) throws -> [any SecureIdentityKey] { [] }

  func deleteKey(_ key: any SecureIdentityKey, for role: BridgeIdentityRole) throws {}

  func deleteAllKeys(for role: BridgeIdentityRole) throws {}

  func withExclusiveCreation<T>(_ body: () throws -> T) rethrows -> T { try body() }
}
