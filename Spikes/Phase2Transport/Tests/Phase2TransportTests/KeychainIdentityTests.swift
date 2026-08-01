import Foundation
import Security
import Testing

@testable import Phase2Transport

private let signedKeychainTestsEnabled =
  ProcessInfo.processInfo.environment["PHASE2_SIGNED_KEYCHAIN_TESTS"] == "1"

@Suite(.serialized)
struct KeychainIdentityTests {
  @Test(
    .enabled(
      if: signedKeychainTestsEnabled,
      "requires a signed app with an authorized Data Protection Keychain access group"
    )
  )
  func nonExportableIdentitySignsPersistsAndCleansUp() throws {
    let runID = "test-\(UUID().uuidString.lowercased().prefix(12))"
    let namespace = try SpikeKeychainNamespace(runID: runID)
    let store = KeychainIdentityStore(namespace: namespace)
    try ProbeKeychainNamespaceInventory.cleanupAll(primaryRunID: runID)
    var primaryError: Error?
    do {
      let created = try store.create(role: .host)
      let message = Data("content-neutral-proof".utf8)
      let signature = try created.sign(message)
      #expect(created.verify(signature: signature, message: message))
      try created.assertPrivateKeyIsNonExportable()

      let loaded = try store.load(role: .host, expectedSPKISHA256: created.spkiSHA256)
      #expect(P256SPKI.matches(created.spkiDER, loaded.spkiDER))
      #expect(throws: KeychainIdentityError.duplicate) {
        _ = try store.create(role: .host)
      }

      var mismatch = created.spkiSHA256
      mismatch[0] ^= 0xFF
      #expect(throws: KeychainIdentityError.keyMismatch) {
        _ = try store.load(role: .host, expectedSPKISHA256: mismatch)
      }
    } catch {
      primaryError = error
    }
    try ProbeKeychainNamespaceInventory.cleanupAll(primaryRunID: runID)
    if let primaryError {
      throw primaryError
    }
    #expect(throws: KeychainIdentityError.keyMissing) {
      _ = try store.load(role: .host)
    }
  }

  @Test
  func persistentKeychainEvidenceIsExplicitlyUnavailableByDefault() {
    #expect(
      signedKeychainTestsEnabled
        || ProcessInfo.processInfo.environment["PHASE2_SIGNED_KEYCHAIN_TESTS"] == nil
    )
  }

  @Test
  func namespaceRequiresExplicitASCII() throws {
    _ = try SpikeKeychainNamespace(runID: "ascii-123")
    for invalid in ["", "UPPER", "ümlaut", "space value", String(repeating: "a", count: 33)] {
      #expect(throws: KeychainIdentityError.invalidNamespace) {
        _ = try SpikeKeychainNamespace(runID: invalid)
      }
    }
    let inventory = try ProbeKeychainNamespaceInventory.all(primaryRunID: "manual-proof")
    #expect(inventory.map(\.runID).contains("cert-host-probe"))
    #expect(inventory.map(\.runID).contains("cert-tls-probe"))
    #expect(inventory.map(\.runID).contains("cert-next-probe"))
  }

  @Test
  func rotationCanonicalFixtureRolesPinsAndMutations() throws {
    let host = try TestOnlyEphemeralIdentityFactory.make(role: .host)
    let wrongRole = try TestOnlyEphemeralIdentityFactory.make(role: .tls)
    let previousHash = Data(repeating: 0x11, count: 32)
    let nextHash = Data(repeating: 0x22, count: 32)
    let statement = try HostSignedRotationStatement(
      generation: 2,
      notBeforeMilliseconds: 1_000,
      notAfterMilliseconds: 2_000,
      previousSPKISHA256: previousHash,
      nextSPKISHA256: nextHash
    )

    var fixture = Data([0x50, 0x32, 0x52, 0x54, 0x01])
    fixture.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 2])
    fixture.append(contentsOf: [0, 0, 0, 0, 0, 0, 0x03, 0xE8])
    fixture.append(contentsOf: [0, 0, 0, 0, 0, 0, 0x07, 0xD0])
    fixture.append(contentsOf: [0, 0x20])
    fixture.append(Data(repeating: 0x11, count: 32))
    fixture.append(contentsOf: [0, 0x20])
    fixture.append(Data(repeating: 0x22, count: 32))
    #expect(statement.canonicalData == fixture)

    #expect(throws: RotationStatementError.incorrectIdentityRole) {
      _ = try statement.signed(by: wrongRole)
    }
    let signed = try statement.signed(by: host)
    try signed.verify(
      hostIdentity: host,
      previousGeneration: 1,
      nowMilliseconds: 1_500,
      expectedCurrentSPKISHA256: previousHash,
      presentedNextSPKISHA256: nextHash
    )
    #expect(throws: RotationStatementError.incorrectIdentityRole) {
      try signed.verify(
        hostIdentity: wrongRole,
        previousGeneration: 1,
        nowMilliseconds: 1_500,
        expectedCurrentSPKISHA256: previousHash,
        presentedNextSPKISHA256: nextHash
      )
    }

    var wrongCurrent = previousHash
    wrongCurrent[0] ^= 1
    #expect(throws: RotationStatementError.currentSPKIMismatch) {
      try signed.verify(
        hostIdentity: host,
        previousGeneration: 1,
        nowMilliseconds: 1_500,
        expectedCurrentSPKISHA256: wrongCurrent,
        presentedNextSPKISHA256: nextHash
      )
    }
    var wrongNext = nextHash
    wrongNext[0] ^= 1
    #expect(throws: RotationStatementError.nextSPKIMismatch) {
      try signed.verify(
        hostIdentity: host,
        previousGeneration: 1,
        nowMilliseconds: 1_500,
        expectedCurrentSPKISHA256: previousHash,
        presentedNextSPKISHA256: wrongNext
      )
    }
    #expect(throws: RotationStatementError.rollback) {
      try signed.verify(
        hostIdentity: host,
        previousGeneration: 2,
        nowMilliseconds: 1_500,
        expectedCurrentSPKISHA256: previousHash,
        presentedNextSPKISHA256: nextHash
      )
    }
    #expect(throws: RotationStatementError.invalidValidity) {
      try signed.verify(
        hostIdentity: host,
        previousGeneration: 1,
        nowMilliseconds: 3_000,
        expectedCurrentSPKISHA256: previousHash,
        presentedNextSPKISHA256: nextHash
      )
    }

    let mutatedStatements = try [
      HostSignedRotationStatement(
        generation: 3,
        notBeforeMilliseconds: 1_000,
        notAfterMilliseconds: 2_000,
        previousSPKISHA256: previousHash,
        nextSPKISHA256: nextHash
      ),
      HostSignedRotationStatement(
        generation: 2,
        notBeforeMilliseconds: 900,
        notAfterMilliseconds: 2_000,
        previousSPKISHA256: previousHash,
        nextSPKISHA256: nextHash
      ),
      HostSignedRotationStatement(
        generation: 2,
        notBeforeMilliseconds: 1_000,
        notAfterMilliseconds: 2_100,
        previousSPKISHA256: previousHash,
        nextSPKISHA256: nextHash
      ),
      HostSignedRotationStatement(
        generation: 2,
        notBeforeMilliseconds: 1_000,
        notAfterMilliseconds: 2_000,
        previousSPKISHA256: wrongCurrent,
        nextSPKISHA256: nextHash
      ),
      HostSignedRotationStatement(
        generation: 2,
        notBeforeMilliseconds: 1_000,
        notAfterMilliseconds: 2_000,
        previousSPKISHA256: previousHash,
        nextSPKISHA256: wrongNext
      ),
    ]
    for mutated in mutatedStatements {
      let reusedSignature = SignedRotationStatement(statement: mutated, signature: signed.signature)
      #expect(throws: RotationStatementError.signatureInvalid) {
        try reusedSignature.verify(
          hostIdentity: host,
          previousGeneration: 1,
          nowMilliseconds: 1_500,
          expectedCurrentSPKISHA256: mutated.previousSPKISHA256,
          presentedNextSPKISHA256: mutated.nextSPKISHA256
        )
      }
    }
  }
}
