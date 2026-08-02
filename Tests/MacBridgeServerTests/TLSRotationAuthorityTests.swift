import CompanionCrypto
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeServer

final class TLSRotationAuthorityTests: XCTestCase {
  private let fingerprintA = Data(repeating: 0xA1, count: 32)
  private let fingerprintB = Data(repeating: 0xB2, count: 32)
  private let fingerprintC = Data(repeating: 0xC3, count: 32)
  private let validityStart: UInt64 = 1_000
  private let validityEnd: UInt64 = 2_000
  private let withinValidity: UInt64 = 1_500

  private var storage = InMemoryRotationStateStorage()
  private var hostIdentity: BridgeIdentity!

  override func setUpWithError() throws {
    try super.setUpWithError()
    storage = InMemoryRotationStateStorage()
    hostIdentity = try ServerTestFixtures.hostIdentity()
  }

  private func makeAuthority() throws -> TLSRotationAuthority {
    try TLSRotationAuthority(storage: storage)
  }

  private func baselineAuthority() throws -> TLSRotationAuthority {
    let authority = try makeAuthority()
    try authority.initializeBaseline(currentSPKIFingerprint: fingerprintA)
    return authority
  }

  private func signedStatement(
    generation: UInt64,
    current: Data,
    next: Data,
    start: UInt64? = nil,
    end: UInt64? = nil
  ) throws -> SignedTLSRotationStatement {
    let statement = try SecureRotationStatement(
      rotationGeneration: generation,
      currentSPKIFingerprint: current,
      nextSPKIFingerprint: next,
      validityStartEpochSeconds: start ?? validityStart,
      validityEndEpochSeconds: end ?? validityEnd
    )
    let signature = try hostIdentity.signStatement(statement.canonicalEncoding())
    return SignedTLSRotationStatement(statement: statement, signature: signature)
  }

  private func assertThrows<E: Error & Equatable, T>(
    _ expected: E,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> T
  ) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
      XCTAssertEqual(error as? E, expected, file: file, line: line)
    }
  }

  // MARK: - Baseline lifecycle

  func testBaselineInitializesOnceAndPersists() throws {
    let authority = try makeAuthority()
    XCTAssertNil(authority.currentState())
    let baseline = try authority.initializeBaseline(currentSPKIFingerprint: fingerprintA)
    XCTAssertEqual(baseline.rotationGeneration, 0)
    XCTAssertEqual(baseline.currentSPKIFingerprint, fingerprintA)
    XCTAssertNil(baseline.previousSPKIFingerprint)
    XCTAssertNotNil(storage.blob)
    assertThrows(TLSRotationStateError.stateAlreadyInitialized) {
      try authority.initializeBaseline(currentSPKIFingerprint: self.fingerprintB)
    }
  }

  func testOperationsBeforeBaselineFailClosed() throws {
    let authority = try makeAuthority()
    assertThrows(TLSRotationStateError.stateMissing) {
      try authority.makeRotationStatement(
        nextSPKIFingerprint: self.fingerprintB,
        validityStartEpochSeconds: self.validityStart,
        validityEndEpochSeconds: self.validityEnd,
        hostIdentity: self.hostIdentity
      )
    }
    assertThrows(TLSRotationStateError.stateMissing) {
      try authority.apply(
        try self.signedStatement(
          generation: 1, current: self.fingerprintA, next: self.fingerprintB),
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.withinValidity
      )
    }
    assertThrows(TLSRotationStateError.stateMissing) {
      try authority.validateIdentityContinuity(currentSPKIFingerprint: self.fingerprintA)
    }
  }

  // MARK: - Statement production

  func testMakeRotationStatementBindsStoredStateAtNextGeneration() throws {
    let authority = try baselineAuthority()
    let signed = try authority.makeRotationStatement(
      nextSPKIFingerprint: fingerprintB,
      validityStartEpochSeconds: validityStart,
      validityEndEpochSeconds: validityEnd,
      hostIdentity: hostIdentity
    )
    XCTAssertEqual(signed.statement.rotationGeneration, 1)
    XCTAssertEqual(signed.statement.currentSPKIFingerprint, fingerprintA)
    XCTAssertEqual(signed.statement.nextSPKIFingerprint, fingerprintB)
    XCTAssertEqual(signed.signature.count, 64)
    XCTAssertEqual(authority.currentState()?.rotationGeneration, 0)
  }

  func testMakeRotationStatementRequiresHostRole() throws {
    let authority = try baselineAuthority()
    let tlsIdentity = try ServerTestFixtures.tlsIdentity()
    assertThrows(TLSRotationStateError.wrongIdentityRole) {
      try authority.makeRotationStatement(
        nextSPKIFingerprint: self.fingerprintB,
        validityStartEpochSeconds: self.validityStart,
        validityEndEpochSeconds: self.validityEnd,
        hostIdentity: tlsIdentity
      )
    }
  }

  func testGenerationOverflowFailsClosedInsteadOfWrapping() throws {
    let saturated = try TLSRotationState(
      rotationGeneration: .max,
      currentSPKIFingerprint: fingerprintA,
      previousSPKIFingerprint: fingerprintB
    )
    storage.blob = TLSRotationStateBlobCodec.encode(saturated)
    let authority = try makeAuthority()
    assertThrows(TLSRotationStateError.generationOverflow) {
      try authority.makeRotationStatement(
        nextSPKIFingerprint: self.fingerprintC,
        validityStartEpochSeconds: self.validityStart,
        validityEndEpochSeconds: self.validityEnd,
        hostIdentity: self.hostIdentity
      )
    }
  }

  // MARK: - Apply: valid, invalid, expired, rollback

  func testProducedStatementAppliesAndAdvancesPersistedState() throws {
    let authority = try baselineAuthority()
    let signed = try authority.makeRotationStatement(
      nextSPKIFingerprint: fingerprintB,
      validityStartEpochSeconds: validityStart,
      validityEndEpochSeconds: validityEnd,
      hostIdentity: hostIdentity
    )
    let advanced = try authority.apply(
      signed, hostPublicKeyX963: hostIdentity.publicKeyX963, atEpochSeconds: withinValidity)
    XCTAssertEqual(advanced.rotationGeneration, 1)
    XCTAssertEqual(advanced.currentSPKIFingerprint, fingerprintB)
    XCTAssertEqual(advanced.previousSPKIFingerprint, fingerprintA)
    XCTAssertEqual(authority.currentState(), advanced)
    XCTAssertEqual(try TLSRotationStateBlobCodec.decode(XCTUnwrap(storage.blob)), advanced)
  }

  func testTamperedSignatureIsRejected() throws {
    let authority = try baselineAuthority()
    let signed = try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB)
    var tampered = signed.signature
    tampered[0] ^= 0x01
    assertThrows(SecureRotationError.invalidSignature) {
      try authority.apply(
        SignedTLSRotationStatement(statement: signed.statement, signature: tampered),
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.withinValidity
      )
    }
    XCTAssertEqual(authority.currentState()?.rotationGeneration, 0)
  }

  func testWrongHostKeyIsRejected() throws {
    let authority = try baselineAuthority()
    let signed = try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB)
    let otherKey = ServerTestFixtures.tlsKey().publicKey.x963Representation
    assertThrows(SecureRotationError.invalidSignature) {
      try authority.apply(
        signed, hostPublicKeyX963: otherKey, atEpochSeconds: self.withinValidity)
    }
  }

  func testWrongCurrentPinIsRejected() throws {
    let authority = try baselineAuthority()
    let signed = try signedStatement(generation: 1, current: fingerprintC, next: fingerprintB)
    assertThrows(SecureRotationError.currentPinMismatch) {
      try authority.apply(
        signed,
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.withinValidity
      )
    }
  }

  func testStaleGenerationIsRejectedAsRollback() throws {
    let authority = try baselineAuthority()
    try authority.apply(
      try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB),
      hostPublicKeyX963: hostIdentity.publicKeyX963,
      atEpochSeconds: withinValidity
    )
    let stale = try signedStatement(generation: 1, current: fingerprintB, next: fingerprintC)
    assertThrows(SecureRotationError.nonMonotonicGeneration) {
      try authority.apply(
        stale,
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.withinValidity
      )
    }
    XCTAssertEqual(authority.currentState()?.rotationGeneration, 1)
  }

  func testExpiredAndNotYetValidStatementsAreRejected() throws {
    let authority = try baselineAuthority()
    let signed = try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB)
    assertThrows(SecureRotationError.expired) {
      try authority.apply(
        signed,
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.validityEnd + 1
      )
    }
    assertThrows(SecureRotationError.notYetValid) {
      try authority.apply(
        signed,
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.validityStart - 1
      )
    }
    XCTAssertEqual(authority.currentState()?.rotationGeneration, 0)
  }

  func testReplayedStatementAfterRotationIsRejected() throws {
    let authority = try baselineAuthority()
    let signed = try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB)
    try authority.apply(
      signed, hostPublicKeyX963: hostIdentity.publicKeyX963, atEpochSeconds: withinValidity)
    assertThrows(SecureRotationError.currentPinMismatch) {
      try authority.apply(
        signed,
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.withinValidity
      )
    }
  }

  // MARK: - Anti-rollback persistence across reopen

  func testAntiRollbackSurvivesStoreReopen() throws {
    let authority = try baselineAuthority()
    try authority.apply(
      try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB),
      hostPublicKeyX963: hostIdentity.publicKeyX963,
      atEpochSeconds: withinValidity
    )

    let reopened = try makeAuthority()
    XCTAssertEqual(reopened.currentState()?.rotationGeneration, 1)
    XCTAssertEqual(reopened.currentState()?.currentSPKIFingerprint, fingerprintB)
    let stale = try signedStatement(generation: 1, current: fingerprintB, next: fingerprintC)
    assertThrows(SecureRotationError.nonMonotonicGeneration) {
      try reopened.apply(
        stale,
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.withinValidity
      )
    }
    let next = try signedStatement(generation: 2, current: fingerprintB, next: fingerprintC)
    XCTAssertEqual(
      try reopened.apply(
        next,
        hostPublicKeyX963: hostIdentity.publicKeyX963,
        atEpochSeconds: withinValidity
      ).rotationGeneration,
      2
    )
  }

  func testStorageWriteFailureLeavesPreviousStateAuthoritative() throws {
    let authority = try baselineAuthority()
    storage.writeError = .storageUnavailable
    let signed = try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB)
    assertThrows(TLSRotationStateError.storageUnavailable) {
      try authority.apply(
        signed,
        hostPublicKeyX963: self.hostIdentity.publicKeyX963,
        atEpochSeconds: self.withinValidity
      )
    }
    XCTAssertEqual(authority.currentState()?.rotationGeneration, 0)
    XCTAssertEqual(authority.currentState()?.currentSPKIFingerprint, fingerprintA)
  }

  // MARK: - Corrupt persisted state fails closed

  func testCorruptPersistedStateFailsClosedAtOpen() throws {
    storage.blob = Data([0xFF, 0x00, 0x01])
    assertThrows(TLSRotationStateError.corruptState) { try self.makeAuthority() }
  }

  func testTruncatedPersistedStateFailsClosedAtOpen() throws {
    let state = try TLSRotationState(
      rotationGeneration: 2,
      currentSPKIFingerprint: fingerprintB,
      previousSPKIFingerprint: fingerprintA
    )
    storage.blob = TLSRotationStateBlobCodec.encode(state).dropLast()
    assertThrows(TLSRotationStateError.corruptState) { try self.makeAuthority() }
  }

  func testStorageReadFailureFailsClosedAtOpen() throws {
    storage.readError = .storageUnavailable
    assertThrows(TLSRotationStateError.storageUnavailable) { try self.makeAuthority() }
  }

  // MARK: - Identity continuity

  func testIdentityContinuityMatchesStoredFingerprint() throws {
    let authority = try baselineAuthority()
    XCTAssertNoThrow(
      try authority.validateIdentityContinuity(currentSPKIFingerprint: fingerprintA))
    assertThrows(TLSRotationStateError.identityLost) {
      try authority.validateIdentityContinuity(currentSPKIFingerprint: self.fingerprintB)
    }
  }

  func testIdentityContinuityTracksAppliedRotation() throws {
    let authority = try baselineAuthority()
    try authority.apply(
      try signedStatement(generation: 1, current: fingerprintA, next: fingerprintB),
      hostPublicKeyX963: hostIdentity.publicKeyX963,
      atEpochSeconds: withinValidity
    )
    XCTAssertNoThrow(
      try authority.validateIdentityContinuity(currentSPKIFingerprint: fingerprintB))
    assertThrows(TLSRotationStateError.identityLost) {
      try authority.validateIdentityContinuity(currentSPKIFingerprint: self.fingerprintA)
    }
  }
}
