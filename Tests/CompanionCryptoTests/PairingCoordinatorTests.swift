import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

/// Host-side pairing session lifecycle: CSPRNG session creation, the atomic
/// claim-before-verification transition, single-use consumption, expiry,
/// cancellation, and the bounded failed-attempt budget.
final class PairingCoordinatorTests: XCTestCase {
  private func assertFails(
    _ expected: PairingClosedReason,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () async throws -> Void
  ) async {
    do {
      try await body()
      XCTFail("expected \(expected)", file: file, line: line)
    } catch {
      XCTAssertEqual(error as? PairingClosedReason, expected, file: file, line: line)
    }
  }

  private func createdSession(
    clock: TestPairingClock,
    coordinator: PairingCoordinator
  ) async throws -> PairingQRPayload {
    try await coordinator.createSession(
      endpointOrigin: PairingFixtures.origin(),
      selection: CryptoFixtures.selection(),
      tlsSPKIFingerprint: CryptoFixtures.tlsCurrentSPKIFingerprint
    )
  }

  // MARK: - Session creation

  func testCreateSessionDrawsExactlyTwoHundredFiftySixBitValues() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let random = PairingFixtures.hostRandom()
    let coordinator = try PairingFixtures.coordinator(clock: clock, random: random)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)

    XCTAssertEqual(random.requestedCounts, [16, 32, 32])
    XCTAssertEqual(payload.pairingSessionID, CryptoFixtures.pairingSessionID)
    XCTAssertEqual(payload.bootstrapSecret, PairingFixtures.bootstrapSecret)
    XCTAssertEqual(payload.bootstrapSecret.count * 8, 256)
    XCTAssertEqual(
      payload.expiresAtEpochSeconds, PairingFixtures.epoch + PairingPolicy.sessionLifetimeSeconds)
    XCTAssertEqual(payload.hostID, CryptoFixtures.hostID)
    XCTAssertEqual(payload.endpointOrigin, try PairingFixtures.origin())
    XCTAssertEqual(payload.selection, try CryptoFixtures.selection())
    XCTAssertEqual(payload.tlsSPKIFingerprint, CryptoFixtures.tlsCurrentSPKIFingerprint)
    XCTAssertEqual(
      payload.hostIdentityFingerprint,
      SPKIFingerprint.fingerprint(of: CryptoFixtures.hostSigningKey.publicKey)
    )
    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .available)
  }

  func testEntropyFailuresFailClosed() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let failing = try PairingFixtures.coordinator(
      clock: clock, random: ScriptedRandomSource(values: [], failure: true))
    await assertFails(.entropyUnavailable) {
      _ = try await self.createdSession(clock: clock, coordinator: failing)
    }

    let short = try PairingFixtures.coordinator(
      clock: clock, random: ScriptedRandomSource(values: [], truncateTo: 31))
    await assertFails(.entropyUnavailable) {
      _ = try await self.createdSession(clock: clock, coordinator: short)
    }
  }

  func testCreateSessionRejectsUnsupportedSelectionAndFingerprint() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    await assertFails(.selectionRejected) {
      _ = try await coordinator.createSession(
        endpointOrigin: PairingFixtures.origin(),
        selection: CryptoFixtures.alternateMinorSelection(),
        tlsSPKIFingerprint: CryptoFixtures.tlsCurrentSPKIFingerprint
      )
    }
    do {
      _ = try await coordinator.createSession(
        endpointOrigin: PairingFixtures.origin(),
        selection: CryptoFixtures.selection(),
        tlsSPKIFingerprint: Data(repeating: 0x01, count: 31)
      )
      XCTFail("expected a rejected fingerprint length")
    } catch {
      XCTAssertEqual(
        error as? SecureWireValidationError, .invalidField(name: "tlsSPKIFingerprint"))
    }
  }

  // MARK: - Claim

  func testClaimProducesAHostSignedResponseOverTheTranscript() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let acceptance = try await coordinator.claim(request: PairingFixtures.request(for: payload))

    XCTAssertEqual(acceptance.response.pairingSessionID, payload.pairingSessionID)
    XCTAssertEqual(acceptance.response.hostID, CryptoFixtures.hostID)
    XCTAssertEqual(acceptance.response.hostPublicKey, CryptoFixtures.hostPublicKeyX963)
    XCTAssertEqual(acceptance.response.hostNonce, PairingFixtures.hostNonce)
    XCTAssertEqual(acceptance.response.selection, payload.selection)
    XCTAssertTrue(
      SecureTranscriptSignature.isValid(
        acceptance.response.transcriptSignature,
        for: acceptance.transcript.canonicalEncoding(),
        publicKey: CryptoFixtures.hostSigningKey.publicKey
      )
    )
    XCTAssertEqual(acceptance.transcript.bootstrapSecret, payload.bootstrapSecret)
    XCTAssertEqual(acceptance.transcript.endpointOrigin, payload.endpointOrigin.normalized)
    XCTAssertEqual(
      acceptance.verificationPhrase,
      SecureShortAuthenticationString.derive(from: acceptance.transcript)
    )
    // With the CSPRNG scripted to the shared fixtures, the state machine
    // reproduces the Step 2.3 golden pairing transcript byte for byte.
    XCTAssertEqual(acceptance.transcript, try CryptoFixtures.pairingTranscript())
    XCTAssertEqual(
      acceptance.transcript.canonicalEncoding().hexFixture, GoldenVectors.pairingEncodingHex)
    XCTAssertEqual(acceptance.verificationPhrase.displayString, GoldenVectors.sasDisplay)
    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .claimed)
  }

  func testNormalizedEquivalentEndpointOriginIsAccepted() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let request = try PairingFixtures.request(
      for: payload, endpointOrigin: "WSS://192.168.004.20:8443")
    // A non-normalizable origin is a mismatch, even when it "looks" equal.
    await assertFails(.endpointOriginMismatch) {
      _ = try await coordinator.claim(request: request)
    }

    let second = try PairingFixtures.coordinator(clock: clock)
    let payload2 = try await createdSession(clock: clock, coordinator: second)
    let equivalent = try PairingFixtures.request(
      for: payload2, endpointOrigin: "WSS://192.168.4.20:8443")
    _ = try await second.claim(request: equivalent)
  }

  func testEndpointOriginMismatchFailsClosedAfterConsumingTheSecret() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    await assertFails(.endpointOriginMismatch) {
      _ = try await coordinator.claim(
        request: PairingFixtures.request(for: payload, endpointOrigin: "wss://192.168.4.21:8443"))
    }
    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .consumed)
    await assertFails(.secretAlreadyConsumed) {
      _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    }
  }

  func testUnsupportedPairingModeIsUnrepresentableAndRejectedAtDecode() {
    XCTAssertEqual(SecurePairingMode.allCases, [.directLAN])
    let relay = #"""
      {"bootstrapSecret":"tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbU=","deviceNonce":"0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dHR0dE=","devicePublicKey":"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpointOrigin":"wss://192.168.4.20:8443","mode":"relay","pairingSessionID":"11111111-1111-1111-1111-111111111111","selection":{"features":["observe-sync-v1"],"major":1,"minor":1}}
      """#
    XCTAssertThrowsError(
      try JSONDecoder().decode(SecurePairingRequest.self, from: Data(relay.utf8)))
  }

  func testSelectionDowngradeAndUnsupportedVersionsFailClosed() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    for selection in [
      try CryptoFixtures.reducedFeatureSelection(),
      try CryptoFixtures.alternateMinorSelection(),
      try CryptoFixtures.alternateMajorSelection(),
    ] {
      let coordinator = try PairingFixtures.coordinator(clock: clock)
      let payload = try await createdSession(clock: clock, coordinator: coordinator)
      await assertFails(.selectionRejected) {
        _ = try await coordinator.claim(
          request: PairingFixtures.request(for: payload, selection: selection))
      }
      let state = await coordinator.lifecycle(of: payload.pairingSessionID)
      XCTAssertEqual(state, .consumed)
    }
  }

  func testInvalidDevicePublicKeyFailsClosedAfterConsumingTheSecret() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    var offCurve = CryptoFixtures.devicePublicKeyX963
    offCurve[40] ^= 0xFF
    await assertFails(.deviceKeyInvalid) {
      _ = try await coordinator.claim(
        request: PairingFixtures.request(for: payload, devicePublicKey: offCurve))
    }
    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .consumed)
  }

  func testHostSignerFailuresFailClosed() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    for signer in [
      FailingTranscriptSigner() as any PairingTranscriptSigner, ShortTranscriptSigner(),
    ] {
      let coordinator = try PairingFixtures.coordinator(clock: clock, signer: signer)
      let payload = try await createdSession(clock: clock, coordinator: coordinator)
      await assertFails(.hostSignatureUnavailable) {
        _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
      }
      let state = await coordinator.lifecycle(of: payload.pairingSessionID)
      XCTAssertEqual(state, .consumed)
    }
  }

  func testUnknownPairingSessionFailsClosed() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let foreign = try PairingFixtures.qrPayload(pairingSessionID: CryptoFixtures.otherUUID)
    await assertFails(.unknownPairingSession) {
      _ = try await coordinator.claim(request: PairingFixtures.request(for: foreign))
    }
    let state = await coordinator.lifecycle(of: CryptoFixtures.otherUUID)
    XCTAssertNil(state)
    let live = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertNotNil(live)
  }

  // MARK: - Single-use semantics

  func testWrongSecretIsRejectedWithoutSpendingTheSession() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    await assertFails(.bootstrapSecretMismatch) {
      _ = try await coordinator.claim(
        request: PairingFixtures.request(
          for: payload, bootstrapSecret: Data(repeating: 0x00, count: 32)))
    }
    var state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .available)

    _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .claimed)
  }

  func testRepeatedFailedClaimsDestroyTheSession() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let wrong = try PairingFixtures.request(
      for: payload, bootstrapSecret: Data(repeating: 0x01, count: 32))

    for _ in 0..<(PairingPolicy.maxFailedClaimAttempts - 1) {
      await assertFails(.bootstrapSecretMismatch) {
        _ = try await coordinator.claim(request: wrong)
      }
    }
    await assertFails(.attemptLimitExceeded) {
      _ = try await coordinator.claim(request: wrong)
    }
    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .destroyed(.attemptLimitExceeded))
    // Even the correct secret can no longer claim a destroyed session.
    await assertFails(.attemptLimitExceeded) {
      _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    }
  }

  func testConcurrentClaimsHaveExactlyOneWinner() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let request = try PairingFixtures.request(for: payload)

    let outcomes = await withTaskGroup(of: PairingClosedReason?.self) { group in
      for _ in 0..<8 {
        group.addTask {
          do {
            _ = try await coordinator.claim(request: request)
            return nil
          } catch {
            return error as? PairingClosedReason
          }
        }
      }
      var collected: [PairingClosedReason?] = []
      for await outcome in group {
        collected.append(outcome)
      }
      return collected
    }

    XCTAssertEqual(outcomes.filter { $0 == nil }.count, 1, "exactly one claimant may win")
    XCTAssertEqual(outcomes.filter { $0 == .sessionAlreadyClaimed }.count, 7)
    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .claimed)
  }

  func testTwoCoordinatorsSharingOneStoreHaveExactlyOneWinner() async throws {
    // The listener creates one coordinator per connection over a shared
    // store, so claim atomicity must hold at the store, not per actor.
    let clock = TestPairingClock(PairingFixtures.epoch)
    let store = InMemoryPairingSessionStore()
    let first = try PairingFixtures.coordinator(clock: clock, store: store)
    let second = try PairingFixtures.coordinator(
      clock: clock, random: PairingFixtures.hostRandom(), store: store)
    let payload = try await createdSession(clock: clock, coordinator: first)
    let request = try PairingFixtures.request(for: payload)

    // Deterministic ordering: the second coordinator sees the claim commit.
    _ = try await first.claim(request: request)
    await assertFails(.sessionAlreadyClaimed) {
      _ = try await second.claim(request: request)
    }

    // Concurrent ordering across both coordinators over one fresh session.
    let raceStore = InMemoryPairingSessionStore()
    let left = try PairingFixtures.coordinator(clock: clock, store: raceStore)
    let right = try PairingFixtures.coordinator(
      clock: clock, random: PairingFixtures.hostRandom(), store: raceStore)
    let racePayload = try await createdSession(clock: clock, coordinator: left)
    let raceRequest = try PairingFixtures.request(for: racePayload)

    let outcomes = await withTaskGroup(of: PairingClosedReason?.self) { group in
      for index in 0..<8 {
        group.addTask {
          let coordinator = index.isMultiple(of: 2) ? left : right
          do {
            _ = try await coordinator.claim(request: raceRequest)
            return nil
          } catch {
            return error as? PairingClosedReason
          }
        }
      }
      var collected: [PairingClosedReason?] = []
      for await outcome in group {
        collected.append(outcome)
      }
      return collected
    }
    XCTAssertEqual(outcomes.filter { $0 == nil }.count, 1, "one QR secret, one signed transcript")
    XCTAssertEqual(outcomes.filter { $0 == .sessionAlreadyClaimed }.count, 7)
  }

  func testReuseAfterSuccessfulPairingIsRejected() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let acceptance = try await coordinator.claim(request: PairingFixtures.request(for: payload))

    let confirmation = try SecurePairingConfirmation(
      pairingSessionID: payload.pairingSessionID,
      deviceID: PairingFixtures.deviceID,
      transcriptSignature: SecureTranscriptSignature.sign(
        acceptance.transcript.canonicalEncoding(), using: CryptoFixtures.deviceSigningKey)
    )
    _ = try await coordinator.confirmVerificationPhrase(
      pairingSessionID: payload.pairingSessionID, phrase: acceptance.verificationPhrase)
    guard case .completed = try await coordinator.submitDeviceConfirmation(confirmation) else {
      return XCTFail("dual confirmation must complete pairing")
    }

    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .consumed)
    await assertFails(.secretAlreadyConsumed) {
      _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    }
  }

  // MARK: - Expiry and cancellation

  func testExpiryBoundaryIsInclusive() async throws {
    let beforeClock = TestPairingClock(PairingFixtures.epoch)
    let before = try PairingFixtures.coordinator(clock: beforeClock)
    let beforePayload = try await createdSession(clock: beforeClock, coordinator: before)
    beforeClock.set(beforePayload.expiresAtEpochSeconds - 1)
    _ = try await before.claim(request: PairingFixtures.request(for: beforePayload))

    let atClock = TestPairingClock(PairingFixtures.epoch)
    let atExpiry = try PairingFixtures.coordinator(clock: atClock)
    let atPayload = try await createdSession(clock: atClock, coordinator: atExpiry)
    atClock.set(atPayload.expiresAtEpochSeconds)
    let expiredState = await atExpiry.lifecycle(of: atPayload.pairingSessionID)
    XCTAssertEqual(expiredState, .destroyed(.sessionExpired))
    await assertFails(.sessionExpired) {
      _ = try await atExpiry.claim(request: PairingFixtures.request(for: atPayload))
    }
    // The expiry transition is persisted, so later attempts stay rejected.
    atClock.set(PairingFixtures.epoch)
    await assertFails(.sessionExpired) {
      _ = try await atExpiry.claim(request: PairingFixtures.request(for: atPayload))
    }
  }

  func testExpiryAfterClaimRejectsConfirmations() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let acceptance = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    clock.set(payload.expiresAtEpochSeconds)
    let expired = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(expired, .destroyed(.sessionExpired))

    await assertFails(.sessionExpired) {
      _ = try await coordinator.confirmVerificationPhrase(
        pairingSessionID: payload.pairingSessionID, phrase: acceptance.verificationPhrase)
    }
    await assertFails(.sessionExpired) {
      _ = try await coordinator.submitDeviceConfirmation(
        SecurePairingConfirmation(
          pairingSessionID: payload.pairingSessionID,
          deviceID: PairingFixtures.deviceID,
          transcriptSignature: SecureTranscriptSignature.sign(
            acceptance.transcript.canonicalEncoding(), using: CryptoFixtures.deviceSigningKey)
        )
      )
    }
  }

  func testExpiryIsEnforcedOnTheMonotonicClockOnly() async throws {
    let wall = TestPairingClock(PairingFixtures.epoch)
    let monotonic = TestPairingClock(PairingFixtures.monotonicOrigin)
    let coordinator = try PairingFixtures.coordinator(clock: wall, monotonicClock: monotonic)
    let payload = try await createdSession(clock: wall, coordinator: coordinator)
    XCTAssertEqual(
      payload.expiresAtEpochSeconds, PairingFixtures.epoch + PairingPolicy.sessionLifetimeSeconds)

    // A wall clock jumping past the displayed expiry does not expire it.
    wall.set(payload.expiresAtEpochSeconds + 10_000)
    let stillLive = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(stillLive, .available)

    // The monotonic clock reaching the lifetime does, on a session no
    // operation ever touched.
    monotonic.set(PairingFixtures.monotonicOrigin + PairingPolicy.sessionLifetimeSeconds)
    let expired = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(expired, .destroyed(.sessionExpired))

    // Stepping the wall clock backwards cannot revive it.
    wall.set(PairingFixtures.epoch - 100_000)
    await assertFails(.sessionExpired) {
      _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    }
  }

  func testSweepClearsSecretsAtExpiryAndRemovesRecordsAfterRetention() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let store = InMemoryPairingSessionStore()
    let coordinator = try PairingFixtures.coordinator(clock: clock, store: store)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    // Claim, then abandon the attempt without confirming either side.
    _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    let claimed = store.record(for: payload.pairingSessionID)
    XCTAssertEqual(claimed?.bootstrapSecret, PairingFixtures.bootstrapSecret)
    XCTAssertNotNil(claimed?.transcript)

    clock.set(payload.expiresAtEpochSeconds)
    let removedAtExpiry = await coordinator.sweepExpired()
    XCTAssertEqual(removedAtExpiry, 0, "the tombstone is retained so the reason stays exact")
    let swept = store.record(for: payload.pairingSessionID)
    XCTAssertEqual(swept?.state, .destroyed(.sessionExpired))
    XCTAssertEqual(swept?.bootstrapSecret, Data())
    XCTAssertEqual(swept?.hostNonce, Data())
    XCTAssertNil(swept?.transcript)

    clock.advance(PairingPolicy.expiredRecordRetentionSeconds)
    let removed = await coordinator.sweepExpired()
    XCTAssertEqual(removed, 1)
    XCTAssertNil(store.record(for: payload.pairingSessionID))
    let state = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertNil(state)
  }

  func testOrdinaryOperationsSweepAbandonedSessions() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let store = InMemoryPairingSessionStore()
    let coordinator = try PairingFixtures.coordinator(clock: clock, store: store)
    let abandoned = try await createdSession(clock: clock, coordinator: coordinator)
    clock.advance(
      PairingPolicy.sessionLifetimeSeconds + PairingPolicy.expiredRecordRetentionSeconds)

    // Creating the next session sweeps the abandoned one without a timer.
    let next = try await coordinator.createSession(
      endpointOrigin: PairingFixtures.origin(),
      selection: CryptoFixtures.selection(),
      tlsSPKIFingerprint: CryptoFixtures.tlsCurrentSPKIFingerprint
    )
    XCTAssertNil(store.record(for: abandoned.pairingSessionID))
    XCTAssertNotNil(store.record(for: next.pairingSessionID))
  }

  func testCancellationDestroysTheSession() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    await coordinator.cancel(pairingSessionID: payload.pairingSessionID)
    await coordinator.cancel(pairingSessionID: payload.pairingSessionID)

    let cancelled = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(cancelled, .destroyed(.sessionCancelled))
    await assertFails(.sessionCancelled) {
      _ = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    }
    await assertFails(.sessionCancelled) {
      _ = try await coordinator.confirmVerificationPhrase(
        pairingSessionID: payload.pairingSessionID,
        phrase: PairingFixtures.mismatchedPhrase()
      )
    }
    // Cancelling an unknown session is a no-op.
    await coordinator.cancel(pairingSessionID: CryptoFixtures.otherUUID)
    let unknown = await coordinator.lifecycle(of: CryptoFixtures.otherUUID)
    XCTAssertNil(unknown)
  }

  func testCancellationAfterClaimStopsCompletion() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let acceptance = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    _ = try await coordinator.confirmVerificationPhrase(
      pairingSessionID: payload.pairingSessionID, phrase: acceptance.verificationPhrase)
    await coordinator.cancel(pairingSessionID: payload.pairingSessionID)

    await assertFails(.sessionCancelled) {
      _ = try await coordinator.submitDeviceConfirmation(
        SecurePairingConfirmation(
          pairingSessionID: payload.pairingSessionID,
          deviceID: PairingFixtures.deviceID,
          transcriptSignature: SecureTranscriptSignature.sign(
            acceptance.transcript.canonicalEncoding(), using: CryptoFixtures.deviceSigningKey)
        )
      )
    }
  }

  func testConfirmationBeforeClaimIsRejected() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    await assertFails(.sessionNotClaimed) {
      _ = try await coordinator.confirmVerificationPhrase(
        pairingSessionID: payload.pairingSessionID,
        phrase: PairingFixtures.mismatchedPhrase()
      )
    }
    await assertFails(.sessionNotClaimed) {
      _ = try await coordinator.submitDeviceConfirmation(
        SecurePairingConfirmation(
          pairingSessionID: payload.pairingSessionID,
          deviceID: PairingFixtures.deviceID,
          transcriptSignature: Data(repeating: 0x11, count: 64)
        )
      )
    }
  }

  func testConfirmationForAnotherPairingSessionIsRejected() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let coordinator = try PairingFixtures.coordinator(clock: clock)
    let payload = try await createdSession(clock: clock, coordinator: coordinator)
    let acceptance = try await coordinator.claim(request: PairingFixtures.request(for: payload))
    await assertFails(.unknownPairingSession) {
      _ = try await coordinator.submitDeviceConfirmation(
        SecurePairingConfirmation(
          pairingSessionID: CryptoFixtures.otherUUID,
          deviceID: PairingFixtures.deviceID,
          transcriptSignature: SecureTranscriptSignature.sign(
            acceptance.transcript.canonicalEncoding(), using: CryptoFixtures.deviceSigningKey)
        )
      )
    }
    let stillClaimed = await coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(stillClaimed, .claimed)
  }
}
