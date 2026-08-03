import CompanionProtocol
import CryptoKit
import Foundation
import MacBridgeCore
import MacBridgeServer
import XCTest

@testable import CodexMicroBridge

/// Deterministic listener with injectable start/stop failures that records
/// the order it was driven in.
actor FakeBridgeListener: BridgeListenerControlling {
  private(set) var startCount = 0
  private(set) var stopCount = 0
  private var startFailure: (any Error)?
  private var stopFailure: (any Error)?
  private let trace: CallTrace

  init(trace: CallTrace) { self.trace = trace }

  func failStart(_ error: (any Error)?) { startFailure = error }
  func failStop(_ error: (any Error)?) { stopFailure = error }

  func start() async throws -> ListenerEndpoint {
    startCount += 1
    await trace.note("start")
    if let startFailure { throw startFailure }
    return ListenerEndpoint(
      host: "192.168.1.20", port: 8443, spkiFingerprint: Data(repeating: 0x11, count: 32))
  }

  func stop() async throws {
    stopCount += 1
    await trace.note("stop")
    if let stopFailure { throw stopFailure }
  }
}

/// Shared ordered call log, so the interleaving of listener and
/// advertisement operations is provable.
actor CallTrace {
  private(set) var calls: [String] = []
  func note(_ call: String) { calls.append(call) }
}

/// Publisher that records into the same trace as the listener.
actor TracingBonjourPublisher: ListenerBonjourPublishing {
  private let trace: CallTrace
  private var publishFailure: (any Error)?
  private var removeFailure: (any Error)?

  init(trace: CallTrace) { self.trace = trace }

  func failPublish(_ error: (any Error)?) { publishFailure = error }
  func failRemove(_ error: (any Error)?) { removeFailure = error }

  func publish() async throws {
    await trace.note("publish")
    if let publishFailure { throw publishFailure }
  }

  func remove() async throws {
    await trace.note("remove")
    if let removeFailure { throw removeFailure }
  }
}

/// Step 2.13 LAN control. The controller owns exactly one thing — the order
/// of operations — which is where this feature's failure modes live.
final class BridgeLANControllerTests: XCTestCase {
  private struct StartFailure: Error {}
  private struct PublishFailure: Error {}
  private struct StopFailure: Error {}
  private struct RemoveFailure: Error {}

  // MARK: - Enabling binds first, advertises second

  func testEnablingBindsBeforeAdvertising() async throws {
    let world = await World()

    let endpoint = try await world.controller.enable()

    XCTAssertEqual(endpoint.port, 8443)
    let calls = await world.trace.calls
    XCTAssertEqual(calls, ["start", "publish"])
    let state = await world.controller.currentState()
    XCTAssertEqual(state, .enabled(host: "192.168.1.20", port: 8443))
    let advertising = await world.controller.isAdvertising()
    XCTAssertTrue(advertising)
  }

  func testTheDefaultStateIsOff() async {
    let world = await World()

    let state = await world.controller.currentState()
    let advertising = await world.controller.isAdvertising()

    XCTAssertEqual(state, .disabled)
    XCTAssertFalse(advertising)
  }

  func testAFailedStartAdvertisesNothingAndReportsFailed() async throws {
    let world = await World()
    await world.listener.failStart(StartFailure())

    await assertThrowsErrorAsync(try await world.controller.enable()) { error in
      XCTAssertEqual(error as? BridgeLANFailure, .startupDenied)
    }

    let calls = await world.trace.calls
    XCTAssertEqual(calls, ["start"], "nothing may be advertised after a failed bind")
    let state = await world.controller.currentState()
    XCTAssertEqual(state, .failed(.startupDenied))
    let advertising = await world.controller.isAdvertising()
    XCTAssertFalse(advertising)
  }

  // MARK: - An advertisement failure rolls the bind back

  func testAFailedAdvertisementRollsTheListenerBack() async throws {
    let world = await World()
    await world.publisher.failPublish(PublishFailure())

    await assertThrowsErrorAsync(try await world.controller.enable()) { error in
      XCTAssertEqual(error as? BridgeLANFailure, .advertisementFailed)
    }

    // The rollback stop runs before the caller sees the failure, so the
    // bridge is never reachable-but-unadvertised.
    let calls = await world.trace.calls
    XCTAssertEqual(calls, ["start", "publish", "stop"])
    let state = await world.controller.currentState()
    XCTAssertEqual(state, .failed(.advertisementFailed))
    let advertising = await world.controller.isAdvertising()
    XCTAssertFalse(advertising)
  }

  /// The menu must never claim the LAN is on when it is not.
  func testAFailedEnableNeverReportsEnabled() async throws {
    for failure in ["start", "publish"] {
      let world = await World()
      if failure == "start" {
        await world.listener.failStart(StartFailure())
      } else {
        await world.publisher.failPublish(PublishFailure())
      }

      _ = try? await world.controller.enable()

      let state = await world.controller.currentState()
      guard case .failed = state else {
        return XCTFail("\(failure): expected a failed state, got \(state)")
      }
    }
  }

  // MARK: - Disabling removes the advertisement, then closes

  func testDisablingRemovesTheAdvertisementBeforeClosing() async throws {
    let world = await World()
    try await world.controller.enable()

    try await world.controller.disable()

    let calls = await world.trace.calls
    XCTAssertEqual(calls, ["start", "publish", "remove", "stop"])
    let state = await world.controller.currentState()
    XCTAssertEqual(state, .disabled)
    let advertising = await world.controller.isAdvertising()
    XCTAssertFalse(advertising)
  }

  func testDisablingAnAlreadyDisabledBridgeIsANoOp() async throws {
    let world = await World()

    try await world.controller.disable()

    let calls = await world.trace.calls
    XCTAssertEqual(calls, [])
    let state = await world.controller.currentState()
    XCTAssertEqual(state, .disabled)
  }

  func testAnUnconfirmedRemovalStillClosesAndThenReports() async throws {
    let world = await World()
    try await world.controller.enable()
    await world.publisher.failRemove(RemoveFailure())

    await assertThrowsErrorAsync(try await world.controller.disable()) { error in
      XCTAssertEqual(error as? BridgeLANFailure, .shutdownIncomplete)
    }

    let calls = await world.trace.calls
    XCTAssertEqual(calls, ["start", "publish", "remove", "stop"])
    let stops = await world.listener.stopCount
    XCTAssertEqual(stops, 1, "the listener must close even when removal failed")
  }

  func testAnIncompleteShutdownIsReported() async throws {
    let world = await World()
    try await world.controller.enable()
    await world.listener.failStop(StopFailure())

    await assertThrowsErrorAsync(try await world.controller.disable()) { error in
      XCTAssertEqual(error as? BridgeLANFailure, .shutdownIncomplete)
    }

    let state = await world.controller.currentState()
    XCTAssertEqual(state, .failed(.shutdownIncomplete))
  }

  // MARK: - One-shot listeners

  func testEnablingTwiceIsRefusedRatherThanBindingTwice() async throws {
    let world = await World()
    try await world.controller.enable()

    await assertThrowsErrorAsync(try await world.controller.enable()) { error in
      XCTAssertEqual(error as? BridgeLANFailure, .alreadyRunning)
    }

    let starts = await world.listener.startCount
    XCTAssertEqual(starts, 1)
  }

  /// The hardened listener's lifecycle is one-shot, so re-enabling must build
  /// a fresh one rather than restart the old one.
  func testReEnablingBuildsAFreshListener() async throws {
    let trace = CallTrace()
    let first = FakeBridgeListener(trace: trace)
    let second = FakeBridgeListener(trace: trace)
    let built = BuiltListeners(listeners: [first, second])
    let controller = BridgeLANController(
      makeListener: { built.next() },
      bonjour: ListenerBonjourCoordinator(publisher: TracingBonjourPublisher(trace: trace))
    )

    try await controller.enable()
    try await controller.disable()
    try await controller.enable()

    let firstStarts = await first.startCount
    let secondStarts = await second.startCount
    XCTAssertEqual(firstStarts, 1)
    XCTAssertEqual(secondStarts, 1, "a second enable must build a fresh listener")
  }

  // MARK: - Authorization changes reach the connections

  /// Driven by a **real** authorization-change coordinator, so the enforcer
  /// is proven against the outcome the product actually produces rather than
  /// a hand-built one.
  func testARevocationClosesTheDevicesConnections() async throws {
    let world = try await AuthorizationWorld()
    let recorder = CloseRecorder()
    let enforcer = BridgeAuthorizationEnforcer(close: { deviceID, reason in
      await recorder.record(deviceID: deviceID, reason: reason)
    })

    let outcome = try await world.coordinator.revoke(deviceID: world.deviceID)
    await enforcer.apply(outcome)

    let closed = await recorder.closed
    XCTAssertEqual(closed.count, 1)
    XCTAssertEqual(closed.first?.deviceID, world.deviceID)
    XCTAssertEqual(closed.first?.reason, .deviceRevoked)
  }

  /// A scope reduction asks for reauthentication — which still closes the
  /// current session, because plan §2 invariant 11 requires every affected
  /// connection to be closed *or* reauthenticated, and the old session must
  /// not stay usable either way.
  func testAScopeReductionAlsoClosesTheCurrentSession() async throws {
    let world = try await AuthorizationWorld(projects: ["project-a", "project-b"])
    let recorder = CloseRecorder()
    let enforcer = BridgeAuthorizationEnforcer(close: { deviceID, reason in
      await recorder.record(deviceID: deviceID, reason: reason)
    })

    let outcome = try await world.coordinator.reduceScope(
      deviceID: world.deviceID, permittedProjectIDs: ["project-a"])
    XCTAssertEqual(outcome.connectionAction, .reauthenticate)
    await enforcer.apply(outcome)

    let closed = await recorder.closed
    XCTAssertEqual(closed.count, 1)
    XCTAssertEqual(closed.first?.reason, .authorizationChanged)
  }

  func testAHostGenerationAdvanceClosesEveryDevice() async throws {
    let world = try await AuthorizationWorld(deviceCount: 4)
    let recorder = CloseRecorder()
    let enforcer = BridgeAuthorizationEnforcer(close: { deviceID, reason in
      await recorder.record(deviceID: deviceID, reason: reason)
    })

    let outcomes = try await world.coordinator.invalidateAllDevices()
    await enforcer.apply(outcomes)

    let closed = await recorder.closed
    XCTAssertEqual(Set(closed.map(\.deviceID)), Set(world.allDeviceIDs))
  }

  // MARK: - Fixtures

  private struct World {
    let trace = CallTrace()
    let listener: FakeBridgeListener
    let publisher: TracingBonjourPublisher
    let controller: BridgeLANController

    init() async {
      let trace = self.trace
      listener = FakeBridgeListener(trace: trace)
      publisher = TracingBonjourPublisher(trace: trace)
      let listener = self.listener
      controller = BridgeLANController(
        makeListener: { listener },
        bonjour: ListenerBonjourCoordinator(publisher: publisher)
      )
    }
  }
}

/// A real grant authority, broker, read-cursor store, and
/// authorization-change coordinator.
struct AuthorizationWorld {
  let authority: DeviceGrantAuthority
  let coordinator: AuthorizationChangeCoordinator
  let deviceID: UUID
  let allDeviceIDs: [UUID]

  init(projects: Set<String> = ["project-a"], deviceCount: Int = 1) async throws {
    authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
    var identifiers: [UUID] = []
    for _ in 0..<deviceCount {
      let identifier = UUID()
      _ = try await authority.addGrant(
        deviceID: identifier,
        devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        permittedProjectIDs: projects
      )
      identifiers.append(identifier)
    }
    allDeviceIDs = identifiers
    deviceID = try XCTUnwrap(identifiers.first)

    let table = ThreadProjectTable()
    let broker = DeviceObservationBroker(
      scopes: authority,
      snapshots: EmptyBridgeSnapshotSource(),
      attribution: table,
      journalEpoch: try SystemJournalEpochMint().mintJournalEpoch()
    )
    let readCursors = try DeviceReadCursorStore(
      storage: InMemoryReadCursorStorage(),
      scopes: authority,
      attribution: table,
      clock: { 1_000_000 }
    )
    coordinator = AuthorizationChangeCoordinator(
      authority: authority, broker: broker, readCursors: readCursors)
  }
}

private struct EmptyBridgeSnapshotSource: ObservationSnapshotProviding {
  func currentObservationSnapshot() async -> CompanionStateSnapshot {
    CompanionStateSnapshot(
      generatedAt: Date(timeIntervalSince1970: 1_000_000), latestSequence: 0, threads: [])
  }
}

/// Hands out a scripted sequence of listeners.
final class BuiltListeners: @unchecked Sendable {
  private let lock = NSLock()
  private var listeners: [any BridgeListenerControlling]

  init(listeners: [any BridgeListenerControlling]) {
    self.listeners = listeners
  }

  func next() -> any BridgeListenerControlling {
    lock.lock()
    defer { lock.unlock() }
    return listeners.isEmpty ? listeners.removeFirst() : listeners.removeFirst()
  }
}

/// Records every connection close the enforcer requested.
actor CloseRecorder {
  private(set) var closed: [(deviceID: UUID, reason: SecureCloseReason)] = []

  func record(deviceID: UUID, reason: SecureCloseReason) {
    closed.append((deviceID, reason))
  }
}
