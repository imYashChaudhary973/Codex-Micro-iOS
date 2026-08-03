import CompanionProtocol
import Foundation
import NIOCore
import NIOEmbedded
import XCTest

@testable import MacBridgeServer

/// The Step 2.7 availability defect and its fix.
///
/// The ADR fixes 4 concurrent unauthenticated connections globally and says
/// nothing about their distribution, which made those 4 the total number of
/// simultaneous peers that can be mid-handshake: four cheap connections
/// holding their slots for the full authentication deadline denied the LAN
/// feature to everyone. Two tightenings close it — a per-source share of the
/// global ceiling, and a silence budget for a connection that holds a slot
/// without saying anything.
final class ListenerAvailabilityTests: XCTestCase {
  private let attacker = ListenerSourceKey(numericAddress: "10.0.0.90")
  private let victim = ListenerSourceKey(numericAddress: "10.0.0.91")

  // MARK: - One source can no longer hold every slot

  func testOneSourceCannotOccupyTheWholeUnauthenticatedCeiling() {
    let ceilings = ListenerCeilings()
    let controller = ListenerAdmissionController(ceilings: ceilings, now: { 0 })

    var admitted: [ListenerConnectionTicket] = []
    for _ in 0..<ceilings.maxUnauthenticatedConnectionsPerSource {
      guard case .success(let ticket) = controller.admit(source: attacker) else {
        return XCTFail("the source's own share must be admitted")
      }
      admitted.append(ticket)
    }

    guard case .failure(let rejection) = controller.admit(source: attacker) else {
      return XCTFail("a source past its share must be refused")
    }
    XCTAssertEqual(rejection, .unauthenticatedCapacity)
    XCTAssertEqual(
      controller.unauthenticatedCount(for: attacker),
      ceilings.maxUnauthenticatedConnectionsPerSource
    )
  }

  /// The defect itself: a flooding source must not deny a different peer.
  func testAFloodingSourceLeavesSlotsForAnotherPeer() {
    let controller = ListenerAdmissionController(ceilings: ListenerCeilings(), now: { 0 })

    var held: [ListenerConnectionTicket] = []
    for _ in 0..<20 {
      if case .success(let ticket) = controller.admit(source: attacker) {
        held.append(ticket)
      }
    }

    guard case .success = controller.admit(source: victim) else {
      return XCTFail("a flood from one source must not deny another")
    }
  }

  func testReleasingAndPromotingGiveTheSourceSlotBack() {
    let controller = ListenerAdmissionController(ceilings: ListenerCeilings(), now: { 0 })
    guard case .success(let first) = controller.admit(source: attacker),
      case .success(let second) = controller.admit(source: attacker)
    else { return XCTFail("expected two admissions") }
    XCTAssertEqual(controller.unauthenticatedCount(for: attacker), 2)

    // Promotion frees the slot because an authenticated connection no longer
    // occupies the unauthenticated ceiling.
    first.markAuthenticated()
    XCTAssertEqual(controller.unauthenticatedCount(for: attacker), 1)

    second.release()
    XCTAssertEqual(controller.unauthenticatedCount(for: attacker), 0)
    guard case .success = controller.admit(source: attacker) else {
      return XCTFail("a freed share must be reusable")
    }
  }

  func testPromotionIsNotDoubleCountedOnRelease() {
    let controller = ListenerAdmissionController(ceilings: ListenerCeilings(), now: { 0 })
    guard case .success(let ticket) = controller.admit(source: attacker) else {
      return XCTFail("expected an admission")
    }

    ticket.markAuthenticated()
    ticket.release()

    XCTAssertEqual(controller.unauthenticatedCount(for: attacker), 0)
    XCTAssertEqual(controller.counts.unauthenticated, 0)
  }

  // MARK: - Ceiling consistency

  func testTheDefaultsAreATighteningAndNeverExceedTheADR() throws {
    let ceilings = try ListenerCeilings().validated()

    XCTAssertLessThanOrEqual(
      ceilings.maxUnauthenticatedConnectionsPerSource, ceilings.maxUnauthenticatedConnections)
    XCTAssertLessThan(
      ceilings.unauthenticatedSilenceSeconds, ceilings.authenticationDeadlineSeconds)
    // The ADR's own numbers are untouched.
    XCTAssertEqual(
      ceilings.maxUnauthenticatedConnections,
      SecureTransportLimits.maxUnauthenticatedConnections)
    XCTAssertEqual(
      ceilings.maxConcurrentConnections, SecureTransportLimits.maxConcurrentConnections)
  }

  func testAPerSourceShareAboveTheGlobalCeilingIsRefused() {
    let ceilings = ListenerCeilings(
      maxUnauthenticatedConnections: 2, maxUnauthenticatedConnectionsPerSource: 2)

    XCTAssertNoThrow(try ceilings.validated())
    XCTAssertThrowsError(
      try ListenerCeilings(
        maxUnauthenticatedConnections: 1, maxUnauthenticatedConnectionsPerSource: 2
      ).validated()
    ) { error in
      XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsInconsistent)
    }
  }

  func testASilenceBudgetAtOrAboveTheDeadlineIsRefused() {
    for silence in [20, 21] {
      XCTAssertThrowsError(
        try ListenerCeilings(
          authenticationDeadlineSeconds: 20, unauthenticatedSilenceSeconds: silence
        ).validated(),
        "\(silence)"
      ) { error in
        XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsInconsistent)
      }
    }
    XCTAssertNoThrow(
      try ListenerCeilings(
        authenticationDeadlineSeconds: 20, unauthenticatedSilenceSeconds: 19
      ).validated())
  }

  func testANonPositiveTighteningIsRefused() {
    for ceilings in [
      ListenerCeilings(maxUnauthenticatedConnectionsPerSource: 0),
      ListenerCeilings(unauthenticatedSilenceSeconds: 0),
    ] {
      XCTAssertThrowsError(try ceilings.validated()) { error in
        XCTAssertEqual(error as? ListenerStartupFailure, .ceilingsExceedADR)
      }
    }
  }

  /// Neither tightening has an ADR row of its own, so a value between the
  /// default and the ceiling it is bounded by is a legitimate configuration.
  func testATighterOrLooserButStillBoundedValueIsAccepted() {
    XCTAssertNoThrow(
      try ListenerCeilings(maxUnauthenticatedConnectionsPerSource: 1).validated())
    XCTAssertNoThrow(
      try ListenerCeilings(maxUnauthenticatedConnectionsPerSource: 4).validated())
    XCTAssertNoThrow(try ListenerCeilings(unauthenticatedSilenceSeconds: 19).validated())
  }

  // MARK: - The silence budget

  func testASilentConnectionGivesItsSlotBackBeforeTheDeadline() async throws {
    let harness = try await Harness()

    await harness.channel.testingEventLoop.advanceTime(by: .seconds(5))

    XCTAssertFalse(harness.channel.isActive)
    XCTAssertEqual(harness.logger.count(of: .unauthenticatedSilenceElapsed), 1)
    XCTAssertEqual(harness.logger.count(of: .authenticationDeadlineElapsed), 0)
  }

  func testTheBudgetFiresOnlyAtItsDeadline() async throws {
    let harness = try await Harness()

    await harness.channel.testingEventLoop.advanceTime(by: .seconds(4))
    XCTAssertTrue(harness.channel.isActive)

    await harness.channel.testingEventLoop.advanceTime(by: .seconds(1))
    XCTAssertFalse(harness.channel.isActive)
  }

  /// A peer that is making progress must never be cut off early: every
  /// accepted message rearms the budget.
  func testAnAcceptedMessageRearmsTheBudget() async throws {
    let harness = try await Harness()

    for _ in 0..<3 {
      await harness.channel.testingEventLoop.advanceTime(by: .seconds(4))
      try await harness.sendHandshakeMessage()
      XCTAssertTrue(harness.channel.isActive)
    }

    await harness.channel.testingEventLoop.advanceTime(by: .seconds(5))
    XCTAssertFalse(harness.channel.isActive)
  }

  func testAuthenticationCancelsTheBudget() async throws {
    let harness = try await Harness()

    try await harness.fire(ListenerConnectionAuthenticated())
    await harness.channel.testingEventLoop.advanceTime(by: .seconds(60))

    XCTAssertTrue(harness.channel.isActive)
    XCTAssertEqual(harness.logger.count(of: .unauthenticatedSilenceElapsed), 0)
  }

  // MARK: - Fixtures

  private struct Harness {
    let channel: NIOAsyncTestingChannel
    let logger = InMemoryListenerLogger()
    private let source = ListenerSourceKey(numericAddress: "10.0.0.90")

    init() async throws {
      let ceilings = ListenerCeilings()
      let controller = ListenerAdmissionController(ceilings: ceilings, now: { 0 })
      guard case .success(let ticket) = controller.admit(source: source) else {
        throw AdmissionRefused()
      }
      channel = NIOAsyncTestingChannel()
      try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0))
      try await channel.pipeline.addHandler(
        ListenerHandshakeGateHandler(
          connectionID: UUID(),
          source: source,
          admission: controller,
          ticket: ticket,
          handshake: ScriptedHandshakeHandler(
            repeating: .reply(
              try ListenerHandshakeEnvelope(
                kind: .sessionAuthResponse, payload: Data(#"{"ok":1}"#.utf8)))
          ),
          authenticationDeadline: .seconds(Int64(ceilings.authenticationDeadlineSeconds)),
          silenceBudget: .seconds(Int64(ceilings.unauthenticatedSilenceSeconds)),
          logger: logger
        )
      )
      let pipeline = channel.pipeline
      try await channel.testingEventLoop.executeInContext {
        pipeline.fireUserInboundEventTriggered(ListenerUpgradeCompleted())
      }
    }

    func fire(_ event: some Sendable) async throws {
      let pipeline = channel.pipeline
      try await channel.testingEventLoop.executeInContext {
        pipeline.fireUserInboundEventTriggered(event)
      }
    }

    /// Sends one allowlisted handshake message. The denying handler refuses
    /// it, but admission and the budget rearm happen before dispatch.
    func sendHandshakeMessage() async throws {
      let envelope = try ListenerHandshakeEnvelope(
        kind: .sessionAuthRequest, payload: Data(#"{"probe":1}"#.utf8))
      let encoded = try envelope.encoded()
      var buffer = channel.allocator.buffer(capacity: encoded.count)
      buffer.writeBytes(encoded)
      _ = try? await channel.writeInbound(buffer)
    }
  }

  private struct AdmissionRefused: Error {}
}
