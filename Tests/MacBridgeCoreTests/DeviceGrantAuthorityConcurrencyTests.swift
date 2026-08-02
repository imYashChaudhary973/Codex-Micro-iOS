import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

final class DeviceGrantAuthorityConcurrencyTests: XCTestCase {
  func testConcurrentAddsForDifferentDevicesHaveNoLostUpdate() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    let firstID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    let secondID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    let firstKey = grantTestPublicKey(0x11)
    let secondKey = grantTestPublicKey(0x22)

    async let first = authority.addGrant(deviceID: firstID, devicePublicKey: firstKey)
    async let second = authority.addGrant(deviceID: secondID, devicePublicKey: secondKey)
    _ = try await (first, second)

    let snapshot = try await authority.macAdministrationSnapshot()
    XCTAssertEqual(Set(snapshot.grants.map(\.deviceID)), [firstID, secondID])
    XCTAssertEqual(snapshot.authoritySequence, 2)
    XCTAssertEqual(store.writeLog.count, 2)
  }

  func testConcurrentAddsForSameDeviceProduceOneGrantAndOneDuplicate() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    let deviceID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    let keys = [grantTestPublicKey(0x11), grantTestPublicKey(0x22)]

    let tasks = keys.map { key in
      Task { () -> DeviceGrantAuthorityError? in
        do {
          _ = try await authority.addGrant(deviceID: deviceID, devicePublicKey: key)
          return nil
        } catch {
          return error as? DeviceGrantAuthorityError
        }
      }
    }
    var outcomes: [DeviceGrantAuthorityError?] = []
    for task in tasks {
      outcomes.append(await task.value)
    }

    XCTAssertEqual(outcomes.filter { $0 == nil }.count, 1)
    XCTAssertEqual(outcomes.filter { $0 == .duplicateDevice }.count, 1)
    let snapshot = try await authority.macAdministrationSnapshot()
    XCTAssertEqual(snapshot.grants.count, 1)
  }

  func testConcurrentRevokeAndLookupHaveAValidSerializedOutcome() async throws {
    let authority = DeviceGrantAuthority(storage: InMemoryGrantAuthorityStore(), clock: { 100 })
    let deviceID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: grantTestPublicKey(0x11)
    )

    async let revoked = authority.revoke(deviceID: deviceID)
    async let lookup = grantLookupOutcome(authority: authority, deviceID: deviceID)
    let (revokedRecord, lookupResult) = try await (revoked, lookup)

    XCTAssertEqual(revokedRecord.tombstone?.kind, .revoked)
    switch lookupResult {
    case .success(let record):
      XCTAssertEqual(record.grantRevision, 1)
      XCTAssertNil(record.tombstone)
    case .failure(let error):
      XCTAssertEqual(error, .deviceRevoked)
    }
  }

  func testFailedConcurrentRevokeNeverPublishesUnpersistedTombstone() async throws {
    let store = InMemoryGrantAuthorityStore()
    let authority = DeviceGrantAuthority(storage: store, clock: { 100 })
    let deviceID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    let original = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: grantTestPublicKey(0x11)
    )
    store.failReplacements(with: .storageUnavailable)

    async let revoke = grantMutationOutcome {
      _ = try await authority.revoke(deviceID: deviceID)
    }
    async let lookup = grantLookupOutcome(authority: authority, deviceID: deviceID)
    let (revokeError, lookupResult) = await (revoke, lookup)

    XCTAssertEqual(revokeError, .storageUnavailable)
    switch lookupResult {
    case .success(let record):
      XCTAssertEqual(record, original)
    case .failure(let error):
      XCTAssertEqual(error, .authorityUnavailable)
    }
    // A revoked-but-unpersisted record is never observable in either order.
    if case .failure(let error) = lookupResult {
      XCTAssertNotEqual(error, .deviceRevoked)
    }

    store.failReplacements(with: nil)
    try await authority.reloadFromStore()
    let reloaded = try await authority.authoritativeGrant(deviceID: deviceID)
    XCTAssertEqual(reloaded, original)
  }

  func testConcurrentTouchesSerializeAuthoritySequenceWithoutLostWrites() async throws {
    let store = InMemoryGrantAuthorityStore()
    let clock = TestGrantClock(epochSeconds: 100)
    let authority = DeviceGrantAuthority(storage: store, clock: clock.reader)
    let deviceID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    _ = try await authority.addGrant(
      deviceID: deviceID,
      devicePublicKey: grantTestPublicKey(0x11)
    )
    clock.advance(to: 200)

    try await withThrowingTaskGroup(of: AuthoritativeDeviceGrant.self) { group in
      for _ in 0..<20 {
        group.addTask {
          try await authority.touchLastSeen(deviceID: deviceID)
        }
      }
      for try await record in group {
        XCTAssertEqual(record.lastSeenAtEpochSeconds, 200)
        XCTAssertEqual(record.grantRevision, 1)
      }
    }

    let snapshot = try await authority.macAdministrationSnapshot()
    XCTAssertEqual(snapshot.authoritySequence, 21)
    XCTAssertEqual(store.writeLog.count, 21)
  }

  func testInMemoryStorageSupportsSynchronousConcurrentCalls() async {
    let store = InMemoryGrantAuthorityStore()

    let allLoadsSucceeded = await withTaskGroup(of: Bool.self) { group in
      for value in 1...100 {
        group.addTask {
          do {
            try store.replace(blob: Data([UInt8(value)]))
            guard case .blob = try store.load() else { return false }
            return true
          } catch {
            return false
          }
        }
      }
      var succeeded = true
      for await result in group {
        succeeded = succeeded && result
      }
      return succeeded
    }

    XCTAssertTrue(allLoadsSucceeded)
    XCTAssertEqual(store.writeLog.count, 100)
  }
}

private func grantLookupOutcome(
  authority: DeviceGrantAuthority,
  deviceID: UUID
) async -> Result<AuthoritativeDeviceGrant, DeviceGrantAuthorityError> {
  do {
    return .success(try await authority.authoritativeGrant(deviceID: deviceID))
  } catch let error as DeviceGrantAuthorityError {
    return .failure(error)
  } catch {
    return .failure(.authorityUnavailable)
  }
}

private func grantMutationOutcome(
  _ operation: @Sendable () async throws -> Void
) async -> DeviceGrantAuthorityError? {
  do {
    try await operation()
    return nil
  } catch {
    return error as? DeviceGrantAuthorityError
  }
}

private func grantTestPublicKey(_ firstScalarByte: UInt8) -> Data {
  let scalar = Data((0..<32).map { firstScalarByte + UInt8($0) })
  return try! P256.Signing.PrivateKey(rawRepresentation: scalar).publicKey.x963Representation
}
