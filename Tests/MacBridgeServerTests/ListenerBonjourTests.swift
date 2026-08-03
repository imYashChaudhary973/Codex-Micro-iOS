import Foundation
import Network
import XCTest

@testable import MacBridgeServer

/// Deterministic publisher with injectable publish/remove failures.
actor FakeBonjourPublisher: ListenerBonjourPublishing {
  private(set) var publishCount = 0
  private(set) var removeCount = 0
  private(set) var order: [String] = []
  private var publishFailure: (any Error)?
  private var removeFailure: (any Error)?

  func failPublish(_ error: (any Error)?) { publishFailure = error }
  func failRemove(_ error: (any Error)?) { removeFailure = error }

  func publish() async throws {
    publishCount += 1
    order.append("publish")
    if let publishFailure { throw publishFailure }
  }

  func remove() async throws {
    removeCount += 1
    order.append("remove")
    if let removeFailure { throw removeFailure }
  }

  func note(_ event: String) { order.append(event) }
}

/// Step 2.13 production Bonjour: the exact ADR §12 allowlist and the three
/// lifecycle rules — advertise only after readiness, roll the listener back
/// when publication fails, and remove the record before closing.
final class ListenerBonjourTests: XCTestCase {
  private struct PublishFailure: Error {}
  private struct RemoveFailure: Error {}

  // MARK: - The record is an exact static allowlist

  func testTheRecordCarriesOnlyStaticAllowlistedValues() {
    XCTAssertEqual(ListenerBonjourRecord.instanceName, "Codex Micro")
    XCTAssertEqual(ListenerBonjourRecord.serviceType, "_codexmicro._tcp")
    XCTAssertEqual(ListenerBonjourRecord.domain, "local.")
    XCTAssertEqual(ListenerBonjourRecord.txtRecord, ["v": "1"])
  }

  func testTheInstanceNameIsNotTheHostName() {
    // The record must be byte-identical on every installation, so it can
    // never be the machine's own name.
    XCTAssertNotEqual(ListenerBonjourRecord.instanceName, Host.current().localizedName ?? "")
    XCTAssertNotEqual(ListenerBonjourRecord.instanceName, ProcessInfo.processInfo.hostName)
  }

  func testTheTxtAllowlistRejectsAnyAddedOrChangedKey() {
    XCTAssertTrue(ListenerBonjourRecord.isAllowlisted(txtRecord: ["v": "1"]))

    for candidate in [
      ["v": "1", "host": "example"],
      ["v": "1", "deviceId": "abc"],
      ["v": "1", "fp": "deadbeef"],
      ["v": "2"],
      [:],
    ] {
      XCTAssertFalse(ListenerBonjourRecord.isAllowlisted(txtRecord: candidate), "\(candidate)")
    }
  }

  func testTheRecordContainsNoHostDeviceUserOrFingerprintValue() {
    let encoded =
      ListenerBonjourRecord.instanceName + ListenerBonjourRecord.serviceType
      + ListenerBonjourRecord.domain
      + ListenerBonjourRecord.txtRecord.map { "\($0.key)=\($0.value)" }.joined()

    for forbidden in [
      ProcessInfo.processInfo.hostName, Host.current().localizedName ?? "no-name",
      NSUserName(), NSFullUserName(),
    ] where !forbidden.isEmpty {
      XCTAssertFalse(
        encoded.localizedCaseInsensitiveContains(forbidden), "leaked \(forbidden)")
    }
    for key in ["fingerprint", "spki", "device", "project", "thread", "secret"] {
      XCTAssertFalse(encoded.localizedCaseInsensitiveContains(key), key)
    }
  }

  func testTheServiceIsBuiltFromTheAllowlistedConstants() {
    let service = ListenerBonjourRecord.service()

    XCTAssertEqual(service.name, ListenerBonjourRecord.instanceName)
    XCTAssertEqual(service.type, ListenerBonjourRecord.serviceType)
    XCTAssertEqual(service.domain, ListenerBonjourRecord.domain)
  }

  // MARK: - Advertise only after readiness

  func testTheDefaultBuildAdvertisesNothing() async throws {
    let coordinator = ListenerBonjourCoordinator()

    let published = await coordinator.isPublished
    XCTAssertFalse(published)
  }

  func testPublicationHappensOnlyWhenAsked() async throws {
    let publisher = FakeBonjourPublisher()
    let coordinator = ListenerBonjourCoordinator(publisher: publisher)

    let before = await publisher.publishCount
    XCTAssertEqual(before, 0)

    try await coordinator.publishAfterReadiness(rollback: {})

    let after = await publisher.publishCount
    XCTAssertEqual(after, 1)
    let published = await coordinator.isPublished
    XCTAssertTrue(published)
  }

  func testRepeatedPublicationIsIdempotent() async throws {
    let publisher = FakeBonjourPublisher()
    let coordinator = ListenerBonjourCoordinator(publisher: publisher)

    try await coordinator.publishAfterReadiness(rollback: {})
    try await coordinator.publishAfterReadiness(rollback: {})

    let count = await publisher.publishCount
    XCTAssertEqual(count, 1)
  }

  // MARK: - Publication failure rolls the listener back

  func testAFailedPublicationRollsTheListenerBackBeforeThrowing() async throws {
    let publisher = FakeBonjourPublisher()
    await publisher.failPublish(PublishFailure())
    let logger = InMemoryListenerLogger()
    let coordinator = ListenerBonjourCoordinator(publisher: publisher, logger: logger)

    var rolledBack = false
    do {
      try await coordinator.publishAfterReadiness(rollback: {
        rolledBack = true
        await publisher.note("rollback")
      })
      XCTFail("a failed publication must throw")
    } catch {
      XCTAssertEqual(error as? ListenerBonjourFailure, .publicationFailed)
    }

    XCTAssertTrue(rolledBack, "the listener must be rolled back")
    // The rollback ran before the throw, so no caller can observe a failed
    // publication while the listener is still bound.
    let order = await publisher.order
    XCTAssertEqual(order, ["publish", "rollback"])
    let published = await coordinator.isPublished
    XCTAssertFalse(published)
    XCTAssertEqual(logger.count(of: .bonjourPublishFailed), 1)
    XCTAssertEqual(logger.count(of: .bonjourPublished), 0)
  }

  // MARK: - Disable removes the advertisement before closing

  func testDisableRemovesTheRecordBeforeClosingTheListener() async throws {
    let publisher = FakeBonjourPublisher()
    let logger = InMemoryListenerLogger()
    let coordinator = ListenerBonjourCoordinator(publisher: publisher, logger: logger)
    try await coordinator.publishAfterReadiness(rollback: {})

    try await coordinator.removeThenClose(closeListener: {
      await publisher.note("close")
    })

    let order = await publisher.order
    XCTAssertEqual(order, ["publish", "remove", "close"])
    let published = await coordinator.isPublished
    XCTAssertFalse(published)
    XCTAssertEqual(logger.count(of: .bonjourRemoved), 1)
  }

  /// A record that may still be visible is a reason to report a failure,
  /// never a reason to leave the listener running.
  func testAFailedRemovalStillClosesTheListenerAndThenReports() async throws {
    let publisher = FakeBonjourPublisher()
    await publisher.failRemove(RemoveFailure())
    let logger = InMemoryListenerLogger()
    let coordinator = ListenerBonjourCoordinator(publisher: publisher, logger: logger)
    try await coordinator.publishAfterReadiness(rollback: {})

    var closed = false
    do {
      try await coordinator.removeThenClose(closeListener: {
        closed = true
        await publisher.note("close")
      })
      XCTFail("an unconfirmed removal must throw")
    } catch {
      XCTAssertEqual(error as? ListenerBonjourFailure, .removalFailed)
    }

    XCTAssertTrue(closed, "the listener must close even when removal failed")
    let order = await publisher.order
    XCTAssertEqual(order, ["publish", "remove", "close"])
    XCTAssertEqual(logger.count(of: .bonjourRemoveFailed), 1)
    XCTAssertEqual(logger.count(of: .bonjourRemoved), 0)
  }

  func testClosingWithoutAnAdvertisementSkipsRemoval() async throws {
    let publisher = FakeBonjourPublisher()
    let coordinator = ListenerBonjourCoordinator(publisher: publisher)

    try await coordinator.removeThenClose(closeListener: {
      await publisher.note("close")
    })

    let order = await publisher.order
    XCTAssertEqual(order, ["close"])
    let removals = await publisher.removeCount
    XCTAssertEqual(removals, 0)
  }

  // MARK: - Logging

  func testOnlyClosedCodesReachTheLogger() async throws {
    let publisher = FakeBonjourPublisher()
    let logger = InMemoryListenerLogger()
    let coordinator = ListenerBonjourCoordinator(publisher: publisher, logger: logger)

    try await coordinator.publishAfterReadiness(rollback: {})
    try await coordinator.removeThenClose(closeListener: {})

    for event in logger.events {
      XCTAssertTrue(ListenerLogCode.allCases.contains(event.code))
      XCTAssertGreaterThanOrEqual(event.count, 0)
    }
    XCTAssertEqual(
      Set(logger.events.map(\.code)), [.bonjourPublished, .bonjourRemoved])
  }
}
