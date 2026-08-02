import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

/// End-to-end pairing choreography across both endpoints: mutual transcript
/// signatures, the transcript-bound verification phrase, dual local
/// confirmation, and the observe-with-empty-scope proposal.
final class PairingChoreographyTests: XCTestCase {
  private struct Endpoints {
    let clock: TestPairingClock
    let coordinator: PairingCoordinator
    let device: PairingDeviceEndpoint
  }

  private func makeEndpoints(
    deviceSigner: (any PairingTranscriptSigner)? = nil,
    hostSigner: (any PairingTranscriptSigner)? = nil,
    deviceID: UUID = PairingFixtures.deviceID
  ) throws -> Endpoints {
    let clock = TestPairingClock(PairingFixtures.epoch)
    return Endpoints(
      clock: clock,
      coordinator: try PairingFixtures.coordinator(clock: clock, signer: hostSigner),
      device: try PairingFixtures.deviceEndpoint(
        clock: clock, signer: deviceSigner, deviceID: deviceID)
    )
  }

  private func newSession(_ endpoints: Endpoints) async throws -> PairingQRPayload {
    try await endpoints.coordinator.createSession(
      endpointOrigin: PairingFixtures.origin(),
      selection: CryptoFixtures.selection(),
      tlsSPKIFingerprint: CryptoFixtures.tlsCurrentSPKIFingerprint
    )
  }

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

  // MARK: - Happy path

  func testPairingCompletesOnlyAfterBothConfirmationsAndYieldsObserveScope() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)

    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)

    // Both endpoints reconstruct the identical transcript and phrase.
    XCTAssertEqual(verification.transcript, acceptance.transcript)
    XCTAssertEqual(
      verification.transcript.canonicalEncoding(), acceptance.transcript.canonicalEncoding())
    XCTAssertEqual(verification.verificationPhrase, acceptance.verificationPhrase)
    XCTAssertEqual(verification.verificationPhrase.indices.count, 6)

    let confirmation = try verification.confirmLocally(matching: acceptance.verificationPhrase)
    XCTAssertEqual(confirmation.pairingSessionID, payload.pairingSessionID)
    XCTAssertEqual(confirmation.deviceID, PairingFixtures.deviceID)
    XCTAssertTrue(
      SecureTranscriptSignature.isValid(
        confirmation.transcriptSignature,
        for: acceptance.transcript.canonicalEncoding(),
        publicKey: CryptoFixtures.deviceSigningKey.publicKey
      )
    )

    let afterDevice = try await endpoints.coordinator.submitDeviceConfirmation(confirmation)
    XCTAssertEqual(afterDevice, .awaitingConfirmation)

    let completion = try await endpoints.coordinator.confirmVerificationPhrase(
      pairingSessionID: payload.pairingSessionID, phrase: acceptance.verificationPhrase)
    guard case .completed(let proposal) = completion else {
      return XCTFail("both confirmations must complete pairing")
    }
    XCTAssertEqual(proposal.pairingSessionID, payload.pairingSessionID)
    XCTAssertEqual(proposal.deviceID, PairingFixtures.deviceID)
    XCTAssertEqual(proposal.devicePublicKeyX963, CryptoFixtures.devicePublicKeyX963)
    XCTAssertEqual(proposal.initialGrant, .initial)
    XCTAssertEqual(proposal.initialGrant.capabilities, [.observe])
    XCTAssertTrue(proposal.initialGrant.projectAllowlist.isEmpty)
    XCTAssertEqual(proposal.pairedAtEpochSeconds, PairingFixtures.epoch)

    let state = await endpoints.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .consumed)
  }

  func testHostConfirmationFirstAlsoCompletes() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)

    let afterHost = try await endpoints.coordinator.confirmVerificationPhrase(
      pairingSessionID: payload.pairingSessionID, phrase: acceptance.verificationPhrase)
    XCTAssertEqual(afterHost, .awaitingConfirmation)

    let confirmation = try verification.confirmLocally(matching: verification.verificationPhrase)
    guard
      case .completed(let proposal) = try await endpoints.coordinator.submitDeviceConfirmation(
        confirmation)
    else {
      return XCTFail("both confirmations must complete pairing")
    }
    XCTAssertEqual(proposal.deviceID, PairingFixtures.deviceID)
  }

  // MARK: - One-sided confirmation

  func testOneSidedDeviceConfirmationCompletesNothing() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)

    let progress = try await endpoints.coordinator.submitDeviceConfirmation(
      verification.confirmLocally(matching: verification.verificationPhrase))
    XCTAssertEqual(progress, .awaitingConfirmation)
    let state = await endpoints.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .claimed)
  }

  func testOneSidedHostConfirmationCompletesNothing() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)

    let progress = try await endpoints.coordinator.confirmVerificationPhrase(
      pairingSessionID: payload.pairingSessionID, phrase: acceptance.verificationPhrase)
    XCTAssertEqual(progress, .awaitingConfirmation)
    let state = await endpoints.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .claimed)
  }

  func testHostPhraseMismatchCompletesNothingAndSpendsTheAttempt() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)
    let wrongPhrase = try PairingFixtures.mismatchedPhrase()
    XCTAssertNotEqual(wrongPhrase, acceptance.verificationPhrase)

    await assertFails(.verificationPhraseMismatch) {
      _ = try await endpoints.coordinator.confirmVerificationPhrase(
        pairingSessionID: payload.pairingSessionID, phrase: wrongPhrase)
    }
    let state = await endpoints.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .consumed)
    await assertFails(.secretAlreadyConsumed) {
      _ = try await endpoints.coordinator.submitDeviceConfirmation(
        verification.confirmLocally(matching: verification.verificationPhrase))
    }
  }

  func testDeviceRefusesToConfirmAMismatchedPhrase() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)
    let wrongPhrase = try PairingFixtures.mismatchedPhrase()
    XCTAssertNotEqual(wrongPhrase, acceptance.verificationPhrase)

    XCTAssertThrowsError(try verification.confirmLocally(matching: wrongPhrase)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .verificationPhraseMismatch)
    }
    // Nothing was signed and nothing reached the host.
    let state = await endpoints.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .claimed)
  }

  // MARK: - Signature verification

  func testInvalidDeviceSignatureFailsClosedAndStillSpentTheSecret() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)

    let forged = try SecurePairingConfirmation(
      pairingSessionID: payload.pairingSessionID,
      deviceID: PairingFixtures.deviceID,
      transcriptSignature: SecureTranscriptSignature.sign(
        acceptance.transcript.canonicalEncoding(), using: CryptoFixtures.tlsCurrentKey)
    )
    await assertFails(.deviceSignatureInvalid) {
      _ = try await endpoints.coordinator.submitDeviceConfirmation(forged)
    }
    let state = await endpoints.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .consumed)
    // Claim-before-verification: the single-use secret is spent even though
    // verification failed, so the same QR can never be replayed.
    await assertFails(.secretAlreadyConsumed) {
      _ = try await endpoints.coordinator.claim(
        request: PairingFixtures.request(for: payload))
    }
  }

  func testTamperedDeviceSignatureBitsFailClosed() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)
    let valid = try verification.confirmLocally(matching: acceptance.verificationPhrase)

    let tampered = try SecurePairingConfirmation(
      pairingSessionID: valid.pairingSessionID,
      deviceID: valid.deviceID,
      transcriptSignature: CryptoFixtures.mutated(valid.transcriptSignature, at: 17)
    )
    await assertFails(.deviceSignatureInvalid) {
      _ = try await endpoints.coordinator.submitDeviceConfirmation(tampered)
    }
  }

  func testDeviceRejectsAnInvalidHostSignature() async throws {
    let endpoints = try makeEndpoints(hostSigner: WrongKeyTranscriptSigner())
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)

    XCTAssertThrowsError(try attempt.verifyHostResponse(acceptance.response)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .hostSignatureInvalid)
    }
  }

  func testDeviceRejectsAResponseSignedOverADifferentTranscript() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)

    let mutated = try SecurePairingResponse(
      pairingSessionID: acceptance.response.pairingSessionID,
      hostID: acceptance.response.hostID,
      hostNonce: CryptoFixtures.mutated(acceptance.response.hostNonce, at: 3),
      hostPublicKey: acceptance.response.hostPublicKey,
      selection: acceptance.response.selection,
      transcriptSignature: acceptance.response.transcriptSignature
    )
    XCTAssertThrowsError(try attempt.verifyHostResponse(mutated)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .hostSignatureInvalid)
    }
  }

  func testDeviceRejectsAForeignHostIdentity() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)

    let foreignKey = CryptoFixtures.tlsCurrentKey
    let foreign = try SecurePairingResponse(
      pairingSessionID: acceptance.response.pairingSessionID,
      hostID: acceptance.response.hostID,
      hostNonce: acceptance.response.hostNonce,
      hostPublicKey: foreignKey.publicKey.x963Representation,
      selection: acceptance.response.selection,
      transcriptSignature: acceptance.response.transcriptSignature
    )
    XCTAssertThrowsError(try attempt.verifyHostResponse(foreign)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .hostIdentityMismatch)
    }

    let wrongHostID = try SecurePairingResponse(
      pairingSessionID: acceptance.response.pairingSessionID,
      hostID: CryptoFixtures.otherUUID,
      hostNonce: acceptance.response.hostNonce,
      hostPublicKey: acceptance.response.hostPublicKey,
      selection: acceptance.response.selection,
      transcriptSignature: acceptance.response.transcriptSignature
    )
    XCTAssertThrowsError(try attempt.verifyHostResponse(wrongHostID)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .hostIdentityMismatch)
    }
  }

  func testDeviceRejectsSessionAndSelectionMismatches() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)

    let foreignSession = try SecurePairingResponse(
      pairingSessionID: CryptoFixtures.otherUUID,
      hostID: acceptance.response.hostID,
      hostNonce: acceptance.response.hostNonce,
      hostPublicKey: acceptance.response.hostPublicKey,
      selection: acceptance.response.selection,
      transcriptSignature: acceptance.response.transcriptSignature
    )
    XCTAssertThrowsError(try attempt.verifyHostResponse(foreignSession)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .pairingSessionMismatch)
    }

    let downgraded = try SecurePairingResponse(
      pairingSessionID: acceptance.response.pairingSessionID,
      hostID: acceptance.response.hostID,
      hostNonce: acceptance.response.hostNonce,
      hostPublicKey: acceptance.response.hostPublicKey,
      selection: CryptoFixtures.reducedFeatureSelection(),
      transcriptSignature: acceptance.response.transcriptSignature
    )
    XCTAssertThrowsError(try attempt.verifyHostResponse(downgraded)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .selectionRejected)
    }
  }

  func testTamperedTLSFingerprintInTheQRBreaksTheTranscriptBinding() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let tampered = try PairingQRPayload(
      selection: payload.selection,
      hostID: payload.hostID,
      endpointOrigin: payload.endpointOrigin,
      hostIdentityFingerprint: payload.hostIdentityFingerprint,
      tlsSPKIFingerprint: CryptoFixtures.tlsNextSPKIFingerprint,
      pairingSessionID: payload.pairingSessionID,
      bootstrapSecret: payload.bootstrapSecret,
      expiresAtEpochSeconds: payload.expiresAtEpochSeconds
    )
    let attempt = try endpoints.device.beginPairing(with: tampered)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    XCTAssertNotEqual(
      SecureShortAuthenticationString.derive(from: acceptance.transcript).displayString,
      SecureShortAuthenticationString.derive(
        from: try CryptoFixtures.pairingTranscript(
          hostTLSSPKIFingerprint: CryptoFixtures.tlsNextSPKIFingerprint)
      ).displayString
    )
    XCTAssertThrowsError(try attempt.verifyHostResponse(acceptance.response)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .hostSignatureInvalid)
    }
  }

  // MARK: - Device-side guards

  func testDeviceRejectsAnExpiredPayload() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    endpoints.clock.set(payload.expiresAtEpochSeconds)
    XCTAssertThrowsError(try endpoints.device.beginPairing(with: payload)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .sessionExpired)
    }
    endpoints.clock.set(payload.expiresAtEpochSeconds - 1)
    XCTAssertNoThrow(try endpoints.device.beginPairing(with: payload))
  }

  func testDeviceRejectsAnUnsupportedSelectionInTheQR() async throws {
    let endpoints = try makeEndpoints()
    let payload = try PairingFixtures.qrPayload(
      selection: CryptoFixtures.alternateMinorSelection())
    XCTAssertThrowsError(try endpoints.device.beginPairing(with: payload)) { error in
      XCTAssertEqual(error as? PairingClosedReason, .selectionRejected)
    }
  }

  func testDeviceSignerFailuresFailClosed() async throws {
    for signer in [
      FailingTranscriptSigner() as any PairingTranscriptSigner, ShortTranscriptSigner(),
    ] {
      let endpoints = try makeEndpoints(deviceSigner: signer)
      let payload = try await newSession(endpoints)
      let attempt = try endpoints.device.beginPairing(with: payload)
      let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
      let verification = try attempt.verifyHostResponse(acceptance.response)
      XCTAssertThrowsError(
        try verification.confirmLocally(matching: acceptance.verificationPhrase)
      ) { error in
        XCTAssertEqual(error as? PairingClosedReason, .deviceSignatureUnavailable)
      }
    }
  }

  func testDeviceEntropyFailureFailsClosed() async throws {
    let clock = TestPairingClock(PairingFixtures.epoch)
    let device = try PairingFixtures.deviceEndpoint(
      clock: clock, random: ScriptedRandomSource(values: [], truncateTo: 8))
    XCTAssertThrowsError(try device.beginPairing(with: PairingFixtures.qrPayload())) { error in
      XCTAssertEqual(error as? PairingClosedReason, .entropyUnavailable)
    }
  }

  func testSecondConfirmationWithADifferentDeviceIdentityFailsClosed() async throws {
    let endpoints = try makeEndpoints()
    let payload = try await newSession(endpoints)
    let attempt = try endpoints.device.beginPairing(with: payload)
    let acceptance = try await endpoints.coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)
    let confirmation = try verification.confirmLocally(matching: acceptance.verificationPhrase)
    _ = try await endpoints.coordinator.submitDeviceConfirmation(confirmation)

    let impostor = try SecurePairingConfirmation(
      pairingSessionID: confirmation.pairingSessionID,
      deviceID: PairingFixtures.otherDeviceID,
      transcriptSignature: confirmation.transcriptSignature
    )
    await assertFails(.deviceIdentityMismatch) {
      _ = try await endpoints.coordinator.submitDeviceConfirmation(impostor)
    }
    let state = await endpoints.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(state, .consumed)
  }
}
