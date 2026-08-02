import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeServer

final class BridgeIdentityStoreTests: XCTestCase {
  private var backend = FakeSecureIdentityBackend()
  private var store: BridgeIdentityStore {
    ServerTestFixtures.store(backend: backend)
  }

  override func setUp() {
    super.setUp()
    backend = FakeSecureIdentityBackend()
  }

  private func assertThrows<T>(
    _ expected: BridgeIdentityError,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> T
  ) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
      XCTAssertEqual(error as? BridgeIdentityError, expected, file: file, line: line)
    }
  }

  // MARK: - Creation and round trip

  func testCreateThenLoadRoundTripsSameKey() throws {
    let created = try store.create(role: .host)
    let loaded = try store.load(role: .host)
    XCTAssertEqual(created.spkiFingerprint, loaded.spkiFingerprint)
    XCTAssertEqual(created.publicKeyX963, loaded.publicKeyX963)
    XCTAssertEqual(created.spkiFingerprint.count, 32)
    XCTAssertEqual(created.spkiDER.count, 91)
    XCTAssertEqual(backend.claims[.host], 1)
    XCTAssertEqual(backend.keys[.host]?.count, 1)
  }

  func testCreatedIdentitySignatureVerifiesWithRawSixtyFourBytes() throws {
    let identity = try store.create(role: .host)
    let message = Data("statement".utf8)
    let signature = try identity.signStatement(message)
    XCTAssertEqual(signature.count, 64)
    let publicKey = try identity.publicSigningKey()
    let parsed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
    XCTAssertTrue(publicKey.isValidSignature(parsed, for: message))
  }

  func testRolesAreIndependent() throws {
    let host = try store.create(role: .host)
    let tls = try store.create(role: .tls)
    XCTAssertNotEqual(host.spkiFingerprint, tls.spkiFingerprint)
    XCTAssertEqual(try store.load(role: .host).spkiFingerprint, host.spkiFingerprint)
    XCTAssertEqual(try store.load(role: .tls).spkiFingerprint, tls.spkiFingerprint)
  }

  func testLoadWithMatchingExpectedFingerprintSucceeds() throws {
    let created = try store.create(role: .tls)
    let loaded = try store.load(role: .tls, expectedSPKIFingerprint: created.spkiFingerprint)
    XCTAssertEqual(loaded.spkiFingerprint, created.spkiFingerprint)
  }

  // MARK: - Duplicate and incomplete creation

  func testSecondCreateFailsWithDuplicateAndKeepsOriginalKey() throws {
    let created = try store.create(role: .host)
    assertThrows(.duplicateIdentity) { try self.store.create(role: .host) }
    XCTAssertEqual(try store.load(role: .host).spkiFingerprint, created.spkiFingerprint)
    XCTAssertEqual(backend.keys[.host]?.count, 1)
  }

  func testCreateOverOrphanClaimFailsIncomplete() throws {
    backend.claims[.host] = 1
    assertThrows(.incompleteCreation) { try self.store.create(role: .host) }
    XCTAssertTrue(backend.keys[.host, default: []].isEmpty)
  }

  func testCreateOverClaimWithMultipleKeysFailsMultiplicity() throws {
    backend.claims[.host] = 1
    backend.keys[.host] = [FakeSecureIdentityKey(), FakeSecureIdentityKey()]
    assertThrows(.keyMultiplicity(count: 2)) { try self.store.create(role: .host) }
  }

  func testCreateOverUnclaimedKeyFailsClosedWithoutDestroyingKey() throws {
    let orphan = FakeSecureIdentityKey()
    backend.keys[.host] = [orphan]
    assertThrows(.claimMissing) { try self.store.create(role: .host) }
    XCTAssertTrue(backend.keys[.host]?.first === orphan)
    XCTAssertEqual(backend.claims[.host], 0)
  }

  func testLoadWithClaimButNoKeyFailsIncomplete() throws {
    backend.claims[.tls] = 1
    assertThrows(.incompleteCreation) { try self.store.load(role: .tls) }
  }

  // MARK: - Rollback on post-create failure

  func testExportableCreatedKeyRollsBackClaimAndKey() throws {
    backend.nextCreatedKey = {
      let key = FakeSecureIdentityKey()
      key.exportable = true
      return key
    }
    assertThrows(.privateKeyExportable) { try self.store.create(role: .host) }
    XCTAssertTrue(backend.keys[.host, default: []].isEmpty)
    XCTAssertEqual(backend.claims[.host], 0)
    backend.nextCreatedKey = nil
    XCTAssertNoThrow(try store.create(role: .host))
  }

  func testWrongAttributesOnCreatedKeyRollsBack() throws {
    backend.nextCreatedKey = {
      let key = FakeSecureIdentityKey()
      key.attributesValid = false
      return key
    }
    assertThrows(.attributeMismatch) { try self.store.create(role: .host) }
    XCTAssertTrue(backend.keys[.host, default: []].isEmpty)
    XCTAssertEqual(backend.claims[.host], 0)
  }

  func testPostCreateMultiplicityRollsBackCreatedKeyOnly() throws {
    let intruder = FakeSecureIdentityKey()
    backend.afterCreateKey = { backend in
      backend.keys[.host, default: []].append(intruder)
      backend.afterCreateKey = nil
    }
    assertThrows(.keyMultiplicity(count: 2)) { try self.store.create(role: .host) }
    XCTAssertEqual(backend.keys[.host]?.count, 1)
    XCTAssertTrue(backend.keys[.host]?.first === intruder)
    XCTAssertEqual(backend.claims[.host], 0)
  }

  func testRollbackFailureSurfacesClosedError() throws {
    backend.nextCreatedKey = {
      let key = FakeSecureIdentityKey()
      key.exportable = true
      return key
    }
    backend.deleteKeyError = .keyStoreFailure
    assertThrows(.rollbackFailure) { try self.store.create(role: .host) }
  }

  // MARK: - Wrong, missing, and corrupt identity state

  func testLoadMissingIdentityFailsClosed() {
    assertThrows(.identityMissing) { try self.store.load(role: .host) }
  }

  func testLoadWithWrongAttributesFailsClosed() throws {
    let created = try store.create(role: .tls)
    backend.keys[.tls]?.first?.attributesValid = false
    assertThrows(.attributeMismatch) {
      try self.store.load(role: .tls, expectedSPKIFingerprint: created.spkiFingerprint)
    }
  }

  func testLoadWithExportablePrivateKeyFailsClosed() throws {
    _ = try store.create(role: .tls)
    backend.keys[.tls]?.first?.exportable = true
    assertThrows(.privateKeyExportable) { try self.store.load(role: .tls) }
  }

  func testLoadWithKeyMultiplicityFailsClosed() throws {
    _ = try store.create(role: .host)
    backend.keys[.host, default: []].append(FakeSecureIdentityKey())
    assertThrows(.keyMultiplicity(count: 2)) { try self.store.load(role: .host) }
  }

  func testLoadWithDuplicateClaimsFailsClosed() throws {
    _ = try store.create(role: .host)
    backend.claims[.host] = 2
    assertThrows(.claimStoreFailure) { try self.store.load(role: .host) }
  }

  func testLoadWithUnclaimedKeyFailsClosed() throws {
    backend.keys[.host] = [FakeSecureIdentityKey()]
    assertThrows(.claimMissing) { try self.store.load(role: .host) }
  }

  func testLoadWithLookupErrorFailsClosed() throws {
    _ = try store.create(role: .host)
    backend.existingKeysError = .keyStoreFailure
    assertThrows(.keyStoreFailure) { try self.store.load(role: .host) }
  }

  func testLoadWithClaimLookupErrorFailsClosed() throws {
    _ = try store.create(role: .host)
    backend.claimCountError = .claimStoreFailure
    assertThrows(.claimStoreFailure) { try self.store.load(role: .host) }
  }

  func testLoadWithUnavailablePublicKeyFailsClosed() throws {
    _ = try store.create(role: .host)
    backend.keys[.host]?.first?.publicKeyAvailable = false
    assertThrows(.publicKeyUnavailable) { try self.store.load(role: .host) }
  }

  // MARK: - SPKI mismatch

  func testLoadWithWrongExpectedFingerprintFailsClosed() throws {
    _ = try store.create(role: .tls)
    assertThrows(.fingerprintMismatch) {
      try self.store.load(
        role: .tls, expectedSPKIFingerprint: Data(repeating: 0xAB, count: 32))
    }
  }

  func testFingerprintCheckHappensBeforeExportAssertion() throws {
    _ = try store.create(role: .tls)
    backend.keys[.tls]?.first?.exportable = true
    assertThrows(.fingerprintMismatch) {
      try self.store.load(
        role: .tls, expectedSPKIFingerprint: Data(repeating: 0xAB, count: 32))
    }
  }

  // MARK: - loadOrCreate never replaces

  func testLoadOrCreateDistinguishesCreatedFromExisting() throws {
    let first = try store.loadOrCreate(role: .host)
    guard case .created(let createdIdentity) = first else {
      return XCTFail("expected fresh creation")
    }
    let second = try store.loadOrCreate(role: .host)
    guard case .existing(let existingIdentity) = second else {
      return XCTFail("expected existing identity")
    }
    XCTAssertEqual(createdIdentity.spkiFingerprint, existingIdentity.spkiFingerprint)
    XCTAssertEqual(backend.keys[.host]?.count, 1)
  }

  func testLoadOrCreateWithExpectedFingerprintOverMissingIdentityIsIdentityLoss() {
    assertThrows(.identityLost) {
      try self.store.loadOrCreate(
        role: .host, expectedSPKIFingerprint: Data(repeating: 0xCD, count: 32))
    }
    XCTAssertTrue(backend.keys[.host, default: []].isEmpty)
    XCTAssertEqual(backend.claims[.host, default: 0], 0)
  }

  func testLoadOrCreateNeverReplacesCorruptIdentity() throws {
    let created = try store.create(role: .tls)
    backend.keys[.tls]?.first?.attributesValid = false
    assertThrows(.attributeMismatch) { try self.store.loadOrCreate(role: .tls) }
    backend.keys[.tls]?.first?.attributesValid = true
    XCTAssertEqual(try store.load(role: .tls).spkiFingerprint, created.spkiFingerprint)
  }

  func testLoadOrCreateNeverReplacesOnFingerprintMismatch() throws {
    let created = try store.create(role: .tls)
    assertThrows(.fingerprintMismatch) {
      try self.store.loadOrCreate(
        role: .tls, expectedSPKIFingerprint: Data(repeating: 0xEF, count: 32))
    }
    XCTAssertEqual(try store.load(role: .tls).spkiFingerprint, created.spkiFingerprint)
  }

  func testLoadOrCreateDoesNotCreateOverIncompleteCreation() throws {
    backend.claims[.host] = 1
    assertThrows(.incompleteCreation) { try self.store.loadOrCreate(role: .host) }
    XCTAssertTrue(backend.keys[.host, default: []].isEmpty)
  }

  // MARK: - Reset gating

  func testResetRefusedWhileGrantsExist() throws {
    let created = try store.create(role: .host)
    let gated = ServerTestFixtures.store(backend: backend, resetPermitted: false)
    assertThrows(.resetRefused) { try gated.reset(role: .host) }
    XCTAssertEqual(try store.load(role: .host).spkiFingerprint, created.spkiFingerprint)
  }

  func testResetRefusedWhenPolicyThrows() throws {
    _ = try store.create(role: .host)
    let throwing = BridgeIdentityStore(
      backend: backend,
      resetPolicy: { throw BridgeIdentityError.claimStoreFailure }
    )
    assertThrows(.resetRefused) { try throwing.reset(role: .host) }
    XCTAssertNoThrow(try store.load(role: .host))
  }

  func testResetWithoutGrantsDestroysVerifiedAndAllowsFreshCreate() throws {
    let first = try store.create(role: .host)
    try store.reset(role: .host)
    XCTAssertTrue(backend.keys[.host, default: []].isEmpty)
    XCTAssertEqual(backend.claims[.host, default: 0], 0)
    assertThrows(.identityMissing) { try self.store.load(role: .host) }
    let second = try store.create(role: .host)
    XCTAssertNotEqual(first.spkiFingerprint, second.spkiFingerprint)
  }

  func testResetVerifiesCleanupAndFailsClosedOnResidualState() throws {
    _ = try store.create(role: .host)
    backend.deleteAllKeysSilentlyFails = true
    assertThrows(.cleanupIncomplete) { try self.store.reset(role: .host) }
  }

  func testResetSurfacesBackendFailure() throws {
    _ = try store.create(role: .host)
    backend.deleteAllKeysError = .keyStoreFailure
    assertThrows(.keyStoreFailure) { try self.store.reset(role: .host) }
  }
}
