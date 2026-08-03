import CompanionProtocol
import Foundation
import Network
import XCTest

@testable import MacBridgeServer

/// Fail-closed startup, interface eligibility, and one-shot lifecycle
/// (plan §2 invariants 2/5, §7 gate 1, ADR §8/§14).
final class ListenerStartupTests: XCTestCase {
  private func loopbackConfiguration(
    enabled: Bool = true,
    ceilings: ListenerCeilings = ListenerCeilings()
  ) throws -> ListenerConfiguration {
    let binding = try ListenerInterfaceBinding.testOnlyLoopback()
    return enabled
      ? ListenerConfiguration.testOnlyEnabled(binding: binding, ceilings: ceilings)
      : ListenerConfiguration.disabled(binding: binding)
  }

  private func wifiBinding() throws -> ListenerInterfaceBinding {
    try ListenerInterfaceBinding.validated(
      interface: ListenerInterface(
        identifier: "en0",
        kind: .wifi,
        isUp: true,
        isRunning: true,
        isPointToPoint: false
      ),
      numericAddress: "10.0.0.4",
      policy: ListenerInterfacePolicy()
    )
  }

  private func startupFailure(_ error: any Error) -> ListenerStartupFailure? {
    guard case .startupDenied(let failure) = error as? ListenerError else { return nil }
    return failure
  }

  // MARK: - Default off

  func testListenerIsOffByDefaultAndFailsClosed() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(enabled: false),
      prerequisites: .allPassing(identity: identity)
    )
    do {
      _ = try await listener.start()
      XCTFail("a default-off listener must not bind")
    } catch {
      XCTAssertEqual(startupFailure(error), .notEnabled)
    }
    let snapshot = await listener.snapshot()
    XCTAssertEqual(snapshot.phase, .terminated)
    XCTAssertEqual(snapshot.activeChildren, 0)
    XCTAssertTrue(snapshot.groupShutdown)
    XCTAssertFalse(snapshot.bonjourPublished)
  }

  func testStep27PublishesNoBonjourService() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: .allPassing(identity: identity)
    )
    _ = try await listener.start()
    let running = await listener.snapshot()
    XCTAssertEqual(running.phase, .running)
    XCTAssertFalse(running.bonjourPublished)
    try await listener.stop()
    let stopped = await listener.snapshot()
    XCTAssertFalse(stopped.bonjourPublished)
  }

  // MARK: - Each prerequisite independently

  func testMissingTLSIdentityFailsClosed() async throws {
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: ListenerPrerequisites(
        identity: StubTLSIdentityProvider(identity: nil),
        grantAuthority: StubGrantAuthorityProbe(),
        policy: StubPolicyProbe(),
        codex: StubCodexProbe(),
        liveInterface: NilLiveInterfaceResolver()
      )
    )
    do {
      _ = try await listener.start()
      XCTFail("a missing TLS identity must disable LAN")
    } catch {
      XCTAssertEqual(startupFailure(error), .identityUnavailable)
    }
    let phase = await listener.snapshot().phase
    XCTAssertEqual(phase, .terminated)
  }

  func testUnavailableGrantAuthorityFailsClosed() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: ListenerPrerequisites(
        identity: StubTLSIdentityProvider(identity: identity),
        grantAuthority: StubGrantAuthorityProbe(available: false),
        policy: StubPolicyProbe(),
        codex: StubCodexProbe(),
        liveInterface: NilLiveInterfaceResolver()
      )
    )
    do {
      _ = try await listener.start()
      XCTFail("an unavailable grant authority must disable LAN")
    } catch {
      XCTAssertEqual(startupFailure(error), .grantAuthorityUnavailable)
    }
  }

  func testUnavailablePolicyFailsClosed() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: ListenerPrerequisites(
        identity: StubTLSIdentityProvider(identity: identity),
        grantAuthority: StubGrantAuthorityProbe(),
        policy: StubPolicyProbe(available: false),
        codex: StubCodexProbe(),
        liveInterface: NilLiveInterfaceResolver()
      )
    )
    do {
      _ = try await listener.start()
      XCTFail("an unavailable policy must disable LAN")
    } catch {
      XCTAssertEqual(startupFailure(error), .policyUnavailable)
    }
  }

  func testUnsupportedCodexFailsClosed() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: ListenerPrerequisites(
        identity: StubTLSIdentityProvider(identity: identity),
        grantAuthority: StubGrantAuthorityProbe(),
        policy: StubPolicyProbe(),
        codex: StubCodexProbe(supported: false),
        liveInterface: NilLiveInterfaceResolver()
      )
    )
    do {
      _ = try await listener.start()
      XCTFail("unsupported Codex must disable LAN")
    } catch {
      XCTAssertEqual(startupFailure(error), .codexUnsupported)
    }
  }

  func testIneligibleNetworkConfigurationFailsClosed() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    // A loopback binding under the production policy is ineligible.
    let configuration = ListenerConfiguration.testOnlyEnabled(
      binding: try ListenerInterfaceBinding.testOnlyLoopback(),
      interfacePolicy: ListenerInterfacePolicy()
    )
    let listener = HardenedWSSListener(
      configuration: configuration,
      prerequisites: .allPassing(identity: identity)
    )
    do {
      _ = try await listener.start()
      XCTFail("an ineligible bind target must disable LAN")
    } catch {
      XCTAssertEqual(error as? ListenerError, .invalidBinding)
    }
    let phase = await listener.snapshot().phase
    XCTAssertEqual(phase, .terminated)
  }

  func testUnpinnableLiveInterfaceFailsClosedOnAProductionBinding() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let configuration = ListenerConfiguration.testOnlyEnabled(
      binding: try wifiBinding(),
      interfacePolicy: ListenerInterfacePolicy()
    )
    let listener = HardenedWSSListener(
      configuration: configuration,
      prerequisites: .allPassing(identity: identity)
    )
    do {
      _ = try await listener.start()
      XCTFail("a production binding with no live interface object must fail closed")
    } catch {
      XCTAssertEqual(startupFailure(error), .liveInterfaceUnavailable)
    }
    let phase = await listener.snapshot().phase
    XCTAssertEqual(phase, .terminated)
  }

  func testCeilingsAboveTheADRFailClosed() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(
        ceilings: ListenerCeilings(maxConcurrentConnections: 64)),
      prerequisites: .allPassing(identity: identity)
    )
    do {
      _ = try await listener.start()
      XCTFail("ceilings above the ADR must disable LAN")
    } catch {
      XCTAssertEqual(startupFailure(error), .ceilingsExceedADR)
    }
  }

  func testMutuallyInconsistentCeilingsFailClosed() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    // A cadence tightened inside the authentication deadline is individually
    // inside the ADR but would let an unauthenticated peer reach the
    // server-originated keep-alive path.
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(
        ceilings: ListenerCeilings(pingCadenceSeconds: 20)),
      prerequisites: .allPassing(identity: identity)
    )
    do {
      _ = try await listener.start()
      XCTFail("mutually inconsistent ceilings must disable LAN")
    } catch {
      XCTAssertEqual(startupFailure(error), .ceilingsInconsistent)
    }
    let phase = await listener.snapshot().phase
    XCTAssertEqual(phase, .terminated)
  }

  func testEveryStartupFailureCaseIsIndependentlyReachableOrDocumented() {
    // Each case must be either exercised above or explicitly accounted for.
    let exercised: Set<ListenerStartupFailure> = [
      .notEnabled,
      .identityUnavailable,
      .grantAuthorityUnavailable,
      .policyUnavailable,
      .codexUnsupported,
      .liveInterfaceUnavailable,
      .ceilingsExceedADR,
      .ceilingsInconsistent,
    ]
    let remaining = Set(ListenerStartupFailure.allCases).subtracting(exercised)
    // `networkConfigurationIneligible` surfaces as `ListenerError.invalidBinding`
    // from bind revalidation, which its own test asserts.
    XCTAssertEqual(remaining, [.networkConfigurationIneligible])
  }

  // MARK: - One-shot lifecycle and teardown

  func testTeardownIsCompleteAndTheListenerNeverRestarts() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let logger = InMemoryListenerLogger()
    let configuration = ListenerConfiguration.testOnlyEnabled(
      binding: try ListenerInterfaceBinding.testOnlyLoopback(),
      logger: logger
    )
    let listener = HardenedWSSListener(
      configuration: configuration,
      prerequisites: .allPassing(identity: identity)
    )
    let endpoint = try await listener.start()
    XCTAssertGreaterThan(endpoint.port, 0)
    XCTAssertEqual(endpoint.host, "127.0.0.1")

    try await listener.stop()
    let snapshot = await listener.snapshot()
    XCTAssertEqual(snapshot.phase, .terminated)
    XCTAssertEqual(snapshot.activeChildren, 0)
    XCTAssertEqual(snapshot.authenticatedChildren, 0)
    XCTAssertTrue(snapshot.groupShutdown)
    XCTAssertFalse(snapshot.bonjourPublished)

    // Duplicate stop joins teardown; restart is refused.
    try await listener.stop()
    do {
      _ = try await listener.start()
      XCTFail("a terminated listener must never restart")
    } catch {
      XCTAssertEqual(error as? ListenerError, .terminated)
    }
    XCTAssertEqual(logger.count(of: .listenerReady), 1)
    XCTAssertEqual(logger.count(of: .listenerStopped), 1)
    XCTAssertEqual(logger.count(of: .listenerCleanupFailed), 0)
  }

  func testNothingIsLeftListeningAfterTeardown() async throws {
    let (identity, fingerprint) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: .allPassing(identity: identity)
    )
    let endpoint = try await listener.start()
    try await listener.stop()

    let url = try XCTUnwrap(PinnedProbeWebSocketClient.url(for: endpoint))
    let client = PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: fingerprint,
      deadline: .seconds(2)
    )
    do {
      _ = try await client.exchange(url: url, message: Data([0x01]))
      XCTFail("the port must no longer accept connections")
    } catch {
      // Any failure is acceptable; the point is that nothing answers.
    }
  }

  func testConcurrentStartAndStopAlwaysTerminates() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: .allPassing(identity: identity)
    )
    async let started: ListenerEndpoint? = try? await listener.start()
    async let stopped: Void? = try? await listener.stop()
    _ = await (started, stopped)
    try? await listener.stop()
    let snapshot = await listener.snapshot()
    XCTAssertEqual(snapshot.phase, .terminated)
    XCTAssertEqual(snapshot.activeChildren, 0)
    XCTAssertTrue(snapshot.groupShutdown)
  }

  func testConcurrentStartsAdmitAtMostOneListener() async throws {
    let (identity, _) = try EphemeralTLSIdentity.make()
    let listener = HardenedWSSListener(
      configuration: try loopbackConfiguration(),
      prerequisites: .allPassing(identity: identity)
    )
    async let first: ListenerEndpoint? = try? await listener.start()
    async let second: ListenerEndpoint? = try? await listener.start()
    let endpoints = await [first, second].compactMap { $0 }
    XCTAssertLessThanOrEqual(endpoints.count, 1)
    try? await listener.stop()
    let phase = await listener.snapshot().phase
    XCTAssertEqual(phase, .terminated)
  }

  func testLifecycleStateMachineIsOneShot() throws {
    var machine = ListenerLifecycleStateMachine()
    XCTAssertEqual(machine.phase, .idle)
    XCTAssertNoThrow(try machine.beginStart())
    XCTAssertThrowsError(try machine.beginStart()) { error in
      XCTAssertEqual(error as? ListenerError, .alreadyStarted)
    }
    XCTAssertTrue(machine.completeStart())
    XCTAssertEqual(machine.phase, .running)
    XCTAssertTrue(machine.requestStop())
    XCTAssertEqual(machine.phase, .stopping)
    XCTAssertFalse(machine.requestStop())
    machine.terminate()
    XCTAssertEqual(machine.phase, .terminated)
    XCTAssertThrowsError(try machine.beginStart()) { error in
      XCTAssertEqual(error as? ListenerError, .terminated)
    }
  }

  func testStopDuringStartupCancelsTheStart() throws {
    var machine = ListenerLifecycleStateMachine()
    try machine.beginStart()
    XCTAssertFalse(machine.requestStop())
    XCTAssertFalse(machine.completeStart())
    XCTAssertEqual(machine.phase, .stopping)
  }

  // MARK: - Interface and address eligibility (ADR §8)

  func testOnlyWiFiAndEthernetAreEligibleOutsideTests() {
    let production = ListenerInterfacePolicy()
    for kind in ListenerInterfaceKind.allCases {
      let interface = ListenerInterface(
        identifier: "if0",
        kind: kind,
        isUp: true,
        isRunning: true,
        isPointToPoint: false
      )
      let expected = kind == .wifi || kind == .ethernet
      XCTAssertEqual(production.allows(interface), expected, "\(kind)")
    }
  }

  func testDownRunningAndPointToPointFlagsAreRequired() {
    let policy = ListenerInterfacePolicy()
    let base = ListenerInterface(
      identifier: "en0", kind: .wifi, isUp: true, isRunning: true, isPointToPoint: false)
    XCTAssertTrue(policy.allows(base))
    XCTAssertFalse(
      policy.allows(
        ListenerInterface(
          identifier: "en0", kind: .wifi, isUp: false, isRunning: true, isPointToPoint: false)))
    XCTAssertFalse(
      policy.allows(
        ListenerInterface(
          identifier: "en0", kind: .wifi, isUp: true, isRunning: false, isPointToPoint: false)))
    XCTAssertFalse(
      policy.allows(
        ListenerInterface(
          identifier: "en0", kind: .wifi, isUp: true, isRunning: true, isPointToPoint: true)))
  }

  func testOnlyPrivateIPv4AndULAAddressesBind() throws {
    let interface = ListenerInterface(
      identifier: "en0", kind: .wifi, isUp: true, isRunning: true, isPointToPoint: false)
    let allowed = ["10.0.0.1", "172.16.5.9", "192.168.1.20", "fd00::1", "fdff:1234::9"]
    for address in allowed {
      XCTAssertNoThrow(
        try ListenerInterfaceBinding.validated(
          interface: interface,
          numericAddress: address,
          policy: ListenerInterfacePolicy()
        ), address)
    }
    let denied = [
      "0.0.0.0", "::", "8.8.8.8", "172.32.0.1", "169.254.1.1", "fe80::1",
      "224.0.0.1", "ff02::1", "127.0.0.1", "::1", "203.0.113.7",
    ]
    for address in denied {
      XCTAssertThrowsError(
        try ListenerInterfaceBinding.validated(
          interface: interface,
          numericAddress: address,
          policy: ListenerInterfacePolicy()
        ), address)
    }
  }

  func testHostnamesAreNeverResolvedIntoABinding() {
    let interface = ListenerInterface(
      identifier: "en0", kind: .wifi, isUp: true, isRunning: true, isPointToPoint: false)
    for host in ["localhost", "bridge.local", "example.com", "", " 10.0.0.1", "10.0.0.1 "] {
      XCTAssertThrowsError(
        try ListenerInterfaceBinding.validated(
          interface: interface,
          numericAddress: host,
          policy: ListenerInterfacePolicy()
        )
      ) { error in
        XCTAssertEqual(error as? ListenerInterfaceError, .nonNumericAddress, host)
      }
    }
  }

  func testLoopbackIsOnlyReachableThroughTheTestOnlyFactory() throws {
    let binding = try ListenerInterfaceBinding.testOnlyLoopback()
    XCTAssertEqual(binding.host, "127.0.0.1")
    XCTAssertEqual(binding.interface.kind, .loopback)
    XCTAssertNoThrow(
      try binding.revalidated(policy: ListenerInterfacePolicy(allowLoopbackForTests: true)))
    XCTAssertThrowsError(try binding.revalidated(policy: ListenerInterfacePolicy())) { error in
      XCTAssertEqual(error as? ListenerInterfaceError, .interfaceDenied)
    }
  }

  func testDiscoveryNeverReturnsAnIneligibleBinding() throws {
    let bindings = try ListenerInterfaceDiscovery.eligibleBindings(
      policy: ListenerInterfacePolicy())
    for binding in bindings {
      XCTAssertTrue(ListenerInterfacePolicy().allows(binding.interface))
      XCTAssertNoThrow(try binding.revalidated(policy: ListenerInterfacePolicy()))
      XCTAssertNotEqual(binding.host, "127.0.0.1")
    }
  }

  func testDiscoveryWithLoopbackPolicyStillDeniesTheProductionPolicy() throws {
    let bindings = try ListenerInterfaceDiscovery.eligibleBindings(
      policy: ListenerInterfacePolicy(allowLoopbackForTests: true))
    for binding in bindings where binding.interface.kind == .loopback {
      XCTAssertThrowsError(try binding.revalidated(policy: ListenerInterfacePolicy()))
    }
  }
}
