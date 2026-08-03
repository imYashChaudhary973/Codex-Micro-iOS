import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

/// End-to-end authenticated-session choreography across both endpoints:
/// three messages, mutual signatures over one transcript, identical
/// directional keys, reconnect isolation, and the Step 2.3 frame rules after
/// a reconnect.
final class SessionChoreographyTests: XCTestCase {
  private struct Endpoints {
    let authority: InMemorySessionAuthority
    let store: InMemoryAuthenticatedSessionStore
    let clock: TestPairingClock
    let coordinator: SessionCoordinator
    let device: SessionDeviceEndpoint
  }

  private struct Pair {
    var host: EstablishedHostSession
    var device: EstablishedDeviceSession
    let superseded: AuthenticatedSessionIdentity?
  }

  private func makeEndpoints(
    hostSigner: (any SessionStatementSigner)? = nil,
    deviceSigner: (any SessionStatementSigner)? = nil,
    deviceRandom: (any PairingRandomSource)? = nil,
    pinnedHostPublicKey: Data? = nil,
    pinnedTLSFingerprint: Data? = nil,
    remainingLifetimeSeconds: UInt64? = nil
  ) throws -> Endpoints {
    let authority = try SessionFixtures.authority(
      remainingLifetimeSeconds: remainingLifetimeSeconds)
    let store = InMemoryAuthenticatedSessionStore()
    let clock = TestPairingClock(SessionFixtures.monotonicOrigin)
    return Endpoints(
      authority: authority,
      store: store,
      clock: clock,
      coordinator: try SessionFixtures.coordinator(
        authority: authority, signer: hostSigner, store: store, monotonicClock: clock),
      device: try SessionFixtures.deviceEndpoint(
        signer: deviceSigner,
        hostPublicKeyX963: pinnedHostPublicKey,
        tlsSPKIFingerprint: pinnedTLSFingerprint,
        random: deviceRandom
      )
    )
  }

  private func connect(
    _ endpoints: Endpoints,
    connectionID: UUID = SessionFixtures.connectionID
  ) async throws -> Pair {
    let attempt = try endpoints.device.beginAuthentication()
    let offer = try await endpoints.coordinator.beginAuthentication(
      request: attempt.request, connectionID: connectionID)
    let completion = try attempt.completeAuthentication(with: offer.response)
    let authenticated = try await endpoints.coordinator.completeAuthentication(
      confirmation: completion.confirmation, connectionID: connectionID)
    return Pair(
      host: authenticated.session,
      device: completion.session,
      superseded: authenticated.supersededSession
    )
  }

  // MARK: - Happy path

  func testBothEndpointsSignOneTranscriptAndDeriveTheSameDirectionalKeys() async throws {
    let endpoints = try makeEndpoints()
    var pair = try await connect(endpoints)

    XCTAssertEqual(pair.device.sessionID, pair.host.record.identity.sessionID)
    XCTAssertEqual(pair.device.transcript, pair.host.transcript)
    XCTAssertEqual(
      pair.device.transcript.canonicalEncoding(), pair.host.transcript.canonicalEncoding())
    XCTAssertEqual(
      pair.device.transcript.hostTLSSPKIFingerprint, CryptoFixtures.tlsCurrentSPKIFingerprint)

    let toHost = try pair.device.outbound.seal(CryptoFixtures.framePlaintext0)
    XCTAssertEqual(try pair.host.inbound.open(toHost), CryptoFixtures.framePlaintext0)
    let toDevice = try pair.host.outbound.seal(CryptoFixtures.framePlaintext1)
    XCTAssertEqual(try pair.device.inbound.open(toDevice), CryptoFixtures.framePlaintext1)

    let header = try SecureFrameHeader.decode(fromFrame: toHost)
    XCTAssertEqual(header.counter, 0)
    XCTAssertEqual(header.connectionID, pair.device.sessionID)
    XCTAssertEqual(header.direction, .clientToServer)
    XCTAssertEqual(try SecureFrameHeader.decode(fromFrame: toDevice).counter, 0)
  }

  func testTheDeviceLearnsNoAuthorityStateFromTheHandshake() async throws {
    let endpoints = try makeEndpoints()
    endpoints.authority.advanceGrantRevision(forDevice: SessionFixtures.deviceID)
    let pair = try await connect(endpoints)

    // The device's whole view of the session is the transcript, and the
    // transcript has no authority field to read.
    let dumped = pair.device.transcript.canonicalEncoding()
    XCTAssertEqual(pair.device.transcript.sessionID, pair.host.record.identity.sessionID)
    XCTAssertEqual(dumped, pair.host.transcript.canonicalEncoding())
    // The host still holds the counters the session was admitted under.
    XCTAssertEqual(pair.host.grantRevision, 8)
    XCTAssertEqual(pair.host.authorizedViewEpoch, 3)
    XCTAssertEqual(pair.host.hostGeneration, 1)
  }

  // MARK: - Device-side verification

  func testDeviceRejectsAHostSignatureFromAnUnpinnedKey() async throws {
    let endpoints = try makeEndpoints(hostSigner: WrongKeySessionSigner())
    let attempt = try endpoints.device.beginAuthentication()
    let offer = try await endpoints.coordinator.beginAuthentication(
      request: attempt.request, connectionID: SessionFixtures.connectionID)

    XCTAssertThrowsError(try attempt.completeAuthentication(with: offer.response)) { error in
      XCTAssertEqual(error as? SessionClosedReason, .hostSignatureInvalid)
    }
    XCTAssertTrue(endpoints.store.state().sessions.isEmpty)
  }

  func testDeviceRefusesAReplyWhoseEchoedFieldsDifferFromWhatTheHostSigned() async throws {
    let endpoints = try makeEndpoints()
    let attempt = try endpoints.device.beginAuthentication()
    let offer = try await endpoints.coordinator.beginAuthentication(
      request: attempt.request, connectionID: SessionFixtures.connectionID)
    let signed = offer.response

    let mutations: [(String, SecureSessionAuthResponse)] = [
      ("sessionID", try response(signed, sessionID: CryptoFixtures.otherUUID)),
      (
        "hostNonce",
        try response(signed, hostNonce: CryptoFixtures.mutated(signed.hostNonce, at: 5))
      ),
      (
        "hostEphemeralPublicKey",
        try response(signed, hostEphemeralPublicKey: CryptoFixtures.serverEphemeralPublicKeyX963)
      ),
      (
        "transcriptSignature",
        try response(
          signed, transcriptSignature: CryptoFixtures.mutated(signed.transcriptSignature, at: 3))
      ),
    ]
    for (field, mutated) in mutations {
      XCTAssertThrowsError(try attempt.completeAuthentication(with: mutated), field) { error in
        XCTAssertEqual(error as? SessionClosedReason, .hostSignatureInvalid, field)
      }
    }
  }

  func testDeviceRefusesASessionOfferedUnderADifferentPinnedChannelIdentity() async throws {
    // The device pins the rotated TLS SPKI while the host still offers under
    // the current one: the reconstructed transcript differs, so the host
    // signature cannot verify.
    let endpoints = try makeEndpoints(pinnedTLSFingerprint: CryptoFixtures.tlsNextSPKIFingerprint)
    let attempt = try endpoints.device.beginAuthentication()
    let offer = try await endpoints.coordinator.beginAuthentication(
      request: attempt.request, connectionID: SessionFixtures.connectionID)

    XCTAssertThrowsError(try attempt.completeAuthentication(with: offer.response)) { error in
      XCTAssertEqual(error as? SessionClosedReason, .hostSignatureInvalid)
    }
    XCTAssertTrue(endpoints.store.state().sessions.isEmpty)
  }

  func testDeviceRejectsAReplyThatChangesTheNegotiatedSelection() async throws {
    let endpoints = try makeEndpoints()
    let attempt = try endpoints.device.beginAuthentication()
    let offer = try await endpoints.coordinator.beginAuthentication(
      request: attempt.request, connectionID: SessionFixtures.connectionID)
    let downgraded = try response(
      offer.response, selection: CryptoFixtures.reducedFeatureSelection())

    XCTAssertThrowsError(try attempt.completeAuthentication(with: downgraded)) { error in
      XCTAssertEqual(error as? SessionClosedReason, .selectionRejected)
    }
  }

  func testDeviceSignerAndEntropyFailuresFailClosed() async throws {
    for signer in [FailingSessionSigner() as any SessionStatementSigner, ShortSessionSigner()] {
      let device = try SessionFixtures.deviceEndpoint(signer: signer)
      XCTAssertThrowsError(try device.beginAuthentication()) { error in
        XCTAssertEqual(error as? SessionClosedReason, .deviceSignatureUnavailable)
      }
    }
    for random in [
      ScriptedRandomSource(values: [], failure: true),
      ScriptedRandomSource(values: [], truncateTo: 8),
    ] {
      let device = try SessionFixtures.deviceEndpoint(random: random)
      XCTAssertThrowsError(try device.beginAuthentication()) { error in
        XCTAssertEqual(error as? SessionClosedReason, .entropyUnavailable)
      }
    }
  }

  func testDeviceSignerFailingAtConfirmationTimeCommitsNothing() async throws {
    let endpoints = try makeEndpoints(deviceSigner: SignerFailingAfterFirstUse())
    let attempt = try endpoints.device.beginAuthentication()
    let offer = try await endpoints.coordinator.beginAuthentication(
      request: attempt.request, connectionID: SessionFixtures.connectionID)

    XCTAssertThrowsError(try attempt.completeAuthentication(with: offer.response)) { error in
      XCTAssertEqual(error as? SessionClosedReason, .deviceSignatureUnavailable)
    }
    XCTAssertTrue(endpoints.store.state().sessions.isEmpty)
  }

  func testDeviceRefusesToProposeAnUnsupportedSelection() async throws {
    let endpoints = try makeEndpoints()
    XCTAssertThrowsError(
      try endpoints.device.beginAuthentication(
        selection: CryptoFixtures.alternateMinorSelection())
    ) { error in
      XCTAssertEqual(error as? SessionClosedReason, .selectionRejected)
    }
  }

  // MARK: - Reconnect isolation

  func testReconnectMintsAFreshSessionKeysAndCounterSpaces() async throws {
    let endpoints = try makeEndpoints()
    var first = try await connect(endpoints)
    _ = try first.device.outbound.seal(CryptoFixtures.framePlaintext0)
    _ = try first.host.outbound.seal(CryptoFixtures.framePlaintext1)

    var second = try await connect(endpoints, connectionID: SessionFixtures.otherConnectionID)
    XCTAssertNotEqual(second.device.sessionID, first.device.sessionID)
    XCTAssertNotEqual(
      second.host.transcript.hostEphemeralPublicKey, first.host.transcript.hostEphemeralPublicKey)
    XCTAssertNotEqual(
      second.host.transcript.deviceEphemeralPublicKey,
      first.host.transcript.deviceEphemeralPublicKey)
    XCTAssertNotEqual(second.host.transcript.hostNonce, first.host.transcript.hostNonce)
    XCTAssertNotEqual(second.host.transcript.deviceNonce, first.host.transcript.deviceNonce)
    XCTAssertEqual(second.superseded, first.host.record.identity)

    let toHost = try second.device.outbound.seal(CryptoFixtures.framePlaintext0)
    let toDevice = try second.host.outbound.seal(CryptoFixtures.framePlaintext1)
    XCTAssertEqual(try SecureFrameHeader.decode(fromFrame: toHost).counter, 0)
    XCTAssertEqual(try SecureFrameHeader.decode(fromFrame: toDevice).counter, 0)
    XCTAssertEqual(try second.host.inbound.open(toHost), CryptoFixtures.framePlaintext0)
    XCTAssertEqual(try second.device.inbound.open(toDevice), CryptoFixtures.framePlaintext1)
  }

  func testReconnectDerivesGenuinelyDifferentDirectionalKeys() async throws {
    let endpoints = try makeEndpoints()
    var first = try await connect(endpoints)
    var second = try await connect(endpoints, connectionID: SessionFixtures.otherConnectionID)

    // Rewrite the old frame's session binding to the new session's ID, so the
    // only thing left that can reject it is the key itself. It still fails,
    // which proves the directional keys differ rather than just the IDs.
    var rebound = try first.device.outbound.seal(CryptoFixtures.framePlaintext0)
    rebound.replaceSubrange(5..<21, with: Data(uuid: second.device.sessionID))
    XCTAssertThrowsError(try second.host.inbound.open(rebound)) { error in
      XCTAssertEqual(error as? SecureFrameError, .authenticationFailed)
    }

    var reboundToDevice = try first.host.outbound.seal(CryptoFixtures.framePlaintext1)
    reboundToDevice.replaceSubrange(5..<21, with: Data(uuid: second.device.sessionID))
    XCTAssertThrowsError(try second.device.inbound.open(reboundToDevice)) { error in
      XCTAssertEqual(error as? SecureFrameError, .authenticationFailed)
    }
  }

  func testFramesNeverCrossBetweenSessionsInEitherDirection() async throws {
    let endpoints = try makeEndpoints()
    var first = try await connect(endpoints)
    let oldToHost = try first.device.outbound.seal(CryptoFixtures.framePlaintext0)
    let oldToDevice = try first.host.outbound.seal(CryptoFixtures.framePlaintext1)

    var second = try await connect(endpoints, connectionID: SessionFixtures.otherConnectionID)
    let newToHost = try second.device.outbound.seal(CryptoFixtures.framePlaintext0)
    let newToDevice = try second.host.outbound.seal(CryptoFixtures.framePlaintext1)

    XCTAssertThrowsError(try second.host.inbound.open(oldToHost)) { error in
      XCTAssertEqual(error as? SecureFrameError, .connectionMismatch)
    }
    XCTAssertThrowsError(try second.device.inbound.open(oldToDevice)) { error in
      XCTAssertEqual(error as? SecureFrameError, .connectionMismatch)
    }
    XCTAssertThrowsError(try first.host.inbound.open(newToHost)) { error in
      XCTAssertEqual(error as? SecureFrameError, .connectionMismatch)
    }
    XCTAssertThrowsError(try first.device.inbound.open(newToDevice)) { error in
      XCTAssertEqual(error as? SecureFrameError, .connectionMismatch)
    }
  }

  func testExactNextCounterRulesStillHoldAfterAReconnect() async throws {
    let endpoints = try makeEndpoints()
    _ = try await connect(endpoints)
    var pair = try await connect(endpoints, connectionID: SessionFixtures.otherConnectionID)

    let frame0 = try pair.device.outbound.seal(CryptoFixtures.framePlaintext0)
    let frame1 = try pair.device.outbound.seal(CryptoFixtures.framePlaintext1)
    let frame2 = try pair.device.outbound.seal(CryptoFixtures.framePlaintext0)
    XCTAssertEqual(try pair.host.inbound.open(frame0), CryptoFixtures.framePlaintext0)

    var duplicate = pair.host.inbound
    XCTAssertThrowsError(try duplicate.open(frame0)) { error in
      XCTAssertEqual(error as? SecureFrameError, .duplicateCounter)
    }
    var gap = pair.host.inbound
    XCTAssertThrowsError(try gap.open(frame2)) { error in
      XCTAssertEqual(error as? SecureFrameError, .counterGap)
    }
    XCTAssertEqual(try pair.host.inbound.open(frame1), CryptoFixtures.framePlaintext1)
  }

  func testReflectionAndTamperRejectionsStillHoldAfterAReconnect() async throws {
    let endpoints = try makeEndpoints()
    _ = try await connect(endpoints)
    var pair = try await connect(endpoints, connectionID: SessionFixtures.otherConnectionID)

    let reflected = try pair.host.outbound.seal(CryptoFixtures.framePlaintext0)
    var reflectionOpener = pair.host.inbound
    XCTAssertThrowsError(try reflectionOpener.open(reflected)) { error in
      XCTAssertEqual(error as? SecureFrameError, .invalidDirection)
    }

    let frame = try pair.device.outbound.seal(CryptoFixtures.framePlaintext0)
    var tamperedCiphertext = frame
    tamperedCiphertext[SecureFrameHeader.headerByteCount + 2] ^= 0x01
    var ciphertextOpener = pair.host.inbound
    XCTAssertThrowsError(try ciphertextOpener.open(tamperedCiphertext)) { error in
      XCTAssertEqual(error as? SecureFrameError, .authenticationFailed)
    }

    var tamperedTag = frame
    tamperedTag[frame.count - 1] ^= 0x01
    var tagOpener = pair.host.inbound
    XCTAssertThrowsError(try tagOpener.open(tamperedTag)) { error in
      XCTAssertEqual(error as? SecureFrameError, .authenticationFailed)
    }

    var tamperedConnection = frame
    tamperedConnection[6] ^= 0xFF
    var connectionOpener = pair.host.inbound
    XCTAssertThrowsError(try connectionOpener.open(tamperedConnection)) { error in
      XCTAssertEqual(error as? SecureFrameError, .connectionMismatch)
    }

    XCTAssertEqual(try pair.host.inbound.open(frame), CryptoFixtures.framePlaintext0)
  }

  // MARK: - Statement binding and redaction

  func testAuthenticationStatementIsDomainSeparatedAndFieldBound() throws {
    let statement = try CryptoFixtures.sessionAuthenticationStatement()
    let encoding = statement.canonicalEncoding()
    let domain = Data(CanonicalStatementDomain.sessionAuthenticationStatement.rawValue.utf8)
    XCTAssertEqual(encoding[0], CanonicalStatementVersion.current)
    XCTAssertEqual(Int(encoding[2]), domain.count)
    XCTAssertEqual(encoding.subdata(in: 3..<(3 + domain.count)), domain)
    XCTAssertEqual(encoding.hexFixture, GoldenVectors.sessionAuthStatementEncodingHex)
    XCTAssertEqual(statement.canonicalHash().hexFixture, GoldenVectors.sessionAuthStatementHashHex)

    for (field, mutated) in try CryptoFixtures.mutatedSessionAuthStatements() {
      XCTAssertNotEqual(mutated.canonicalEncoding(), encoding, field)
      XCTAssertNotEqual(mutated.canonicalHash(), statement.canonicalHash(), field)
    }
  }

  func testStatementInitRejectsOutOfBoundsFields() throws {
    XCTAssertThrowsError(
      try SessionAuthenticationStatement(
        hostID: SessionFixtures.hostID,
        deviceID: SessionFixtures.deviceID,
        selection: SessionPolicy.requiredSelection(),
        deviceEphemeralPublicKey: Data(repeating: 0x04, count: 64),
        deviceNonce: CryptoFixtures.sessionDeviceNonce))
    XCTAssertThrowsError(
      try SessionAuthenticationStatement(
        hostID: SessionFixtures.hostID,
        deviceID: SessionFixtures.deviceID,
        selection: SessionPolicy.requiredSelection(),
        deviceEphemeralPublicKey: CryptoFixtures.clientEphemeralPublicKeyX963,
        deviceNonce: Data(repeating: 0xC4, count: 31)))
  }

  func testKeyBearingSessionTypesRedactTheirDescriptions() async throws {
    let endpoints = try makeEndpoints()
    let attempt = try endpoints.device.beginAuthentication()
    let offer = try await endpoints.coordinator.beginAuthentication(
      request: attempt.request, connectionID: SessionFixtures.connectionID)
    let completion = try attempt.completeAuthentication(with: offer.response)
    let authenticated = try await endpoints.coordinator.completeAuthentication(
      confirmation: completion.confirmation, connectionID: SessionFixtures.connectionID)

    XCTAssertEqual(String(describing: authenticated), "HostSessionAuthentication(redacted)")
    XCTAssertEqual(String(describing: authenticated.session), "EstablishedHostSession(redacted)")
    XCTAssertEqual(String(describing: completion), "DeviceSessionCompletion(redacted)")
    XCTAssertEqual(String(describing: completion.session), "EstablishedDeviceSession(redacted)")
    XCTAssertEqual(String(describing: attempt), "SessionDeviceAttempt(redacted)")
    XCTAssertTrue(Mirror(reflecting: authenticated.session).children.isEmpty)
    XCTAssertTrue(Mirror(reflecting: completion.session).children.isEmpty)
    XCTAssertTrue(Mirror(reflecting: attempt).children.isEmpty)

    var dumped = ""
    dump(completion.session, to: &dumped)
    XCTAssertFalse(dumped.contains("outbound"))
    XCTAssertFalse(dumped.contains("inbound"))
  }

  // MARK: - Helpers

  private func response(
    _ base: SecureSessionAuthResponse,
    sessionID: UUID? = nil,
    selection: SecureProtocolSelection? = nil,
    hostEphemeralPublicKey: Data? = nil,
    hostNonce: Data? = nil,
    transcriptSignature: Data? = nil
  ) throws -> SecureSessionAuthResponse {
    try SecureSessionAuthResponse(
      sessionID: sessionID ?? base.sessionID,
      selection: selection ?? base.selection,
      hostEphemeralPublicKey: hostEphemeralPublicKey ?? base.hostEphemeralPublicKey,
      hostNonce: hostNonce ?? base.hostNonce,
      transcriptSignature: transcriptSignature ?? base.transcriptSignature
    )
  }
}
