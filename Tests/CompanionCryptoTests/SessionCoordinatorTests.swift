import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

/// Host-side authenticated-session state machine: the three-message
/// handshake and its single commit point, Mac-authority binding, the
/// collapsed pre-authentication rejection, one active session per device,
/// the authentication generation, linearization against authorization
/// changes, and active-session expiry.
final class SessionCoordinatorTests: XCTestCase {
  private struct Host {
    let authority: InMemorySessionAuthority
    let store: InMemoryAuthenticatedSessionStore
    let clock: TestPairingClock
    let coordinator: SessionCoordinator
  }

  private func makeHost(
    devices: [UUID] = [SessionFixtures.deviceID],
    grantRevision: UInt64 = 7,
    authorizedViewEpoch: UInt64 = 3,
    hostGeneration: UInt64 = 1,
    remainingLifetimeSeconds: UInt64? = nil,
    grantExpiresAtEpochSeconds: UInt64? = nil,
    signer: (any SessionStatementSigner)? = nil,
    random: (any PairingRandomSource)? = nil,
    store: InMemoryAuthenticatedSessionStore? = nil
  ) throws -> Host {
    let authority = try SessionFixtures.authority(
      devices: devices,
      grantRevision: grantRevision,
      authorizedViewEpoch: authorizedViewEpoch,
      hostGeneration: hostGeneration,
      remainingLifetimeSeconds: remainingLifetimeSeconds,
      grantExpiresAtEpochSeconds: grantExpiresAtEpochSeconds
    )
    let store = store ?? InMemoryAuthenticatedSessionStore()
    let clock = TestPairingClock(SessionFixtures.monotonicOrigin)
    return Host(
      authority: authority,
      store: store,
      clock: clock,
      coordinator: try SessionFixtures.coordinator(
        authority: authority,
        signer: signer,
        store: store,
        random: random,
        monotonicClock: clock
      )
    )
  }

  /// Drives all three messages against one coordinator.
  @discardableResult
  private func handshake(
    _ host: Host,
    request: SecureSessionAuthRequest? = nil,
    connectionID: UUID = SessionFixtures.connectionID
  ) async throws -> HostSessionAuthentication {
    let message1 = try request ?? SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: message1, connectionID: connectionID)
    return try await host.coordinator.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offer, request: message1),
      connectionID: connectionID
    )
  }

  private func assertFails(
    _ expected: SessionClosedReason,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () async throws -> Void
  ) async {
    do {
      try await body()
      XCTFail("expected \(expected)", file: file, line: line)
    } catch {
      XCTAssertEqual(error as? SessionClosedReason, expected, file: file, line: line)
    }
  }

  private func nonce(_ byte: UInt8) -> Data {
    Data(repeating: byte, count: 32)
  }

  // MARK: - Commit point

  func testSessionIsRegisteredOnlyAfterTheDeviceConfirmsTheTranscript() async throws {
    let host = try makeHost()
    let request = try SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)

    // Message 2 commits nothing at all.
    XCTAssertTrue(host.store.state().sessions.isEmpty)
    let pendingCount = await host.coordinator.pendingHandshakeCount()
    XCTAssertEqual(pendingCount, 1)

    let authenticated = try await host.coordinator.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offer, request: request),
      connectionID: SessionFixtures.connectionID
    )
    XCTAssertEqual(authenticated.session.record.identity.sessionID, offer.response.sessionID)
    XCTAssertEqual(authenticated.session.record.identity.connectionID, SessionFixtures.connectionID)
    XCTAssertEqual(authenticated.session.record.identity.deviceID, SessionFixtures.deviceID)
    XCTAssertEqual(authenticated.session.record.generation, .first)
    XCTAssertNil(authenticated.supersededSession)
    XCTAssertEqual(host.store.state().sessions.count, 1)
    let settled = await host.coordinator.pendingHandshakeCount()
    XCTAssertEqual(settled, 0)
  }

  func testAuthorityCountersAreHostSideOnlyAndNeverOnTheWire() async throws {
    let host = try makeHost()
    let request = try SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)

    // Neither message carries authority state — there is no field to carry
    // it in, and the encoded reply names none of it.
    let encoded = try JSONEncoder().encode(offer.response)
    let json = String(decoding: encoded, as: UTF8.self)
    for forbidden in ["grantRevision", "authorizedViewEpoch", "hostGeneration"] {
      XCTAssertFalse(json.contains(forbidden))
    }

    let authenticated = try await host.coordinator.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offer, request: request),
      connectionID: SessionFixtures.connectionID
    )
    XCTAssertEqual(authenticated.session.grantRevision, 7)
    XCTAssertEqual(authenticated.session.authorizedViewEpoch, 3)
    XCTAssertEqual(authenticated.session.hostGeneration, 1)
  }

  func testTheSessionIsAdmittedUnderTheAuthorityCurrentAtCommitNotAtOffer() async throws {
    let host = try makeHost()
    let request = try SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)

    // The Mac reduces the grant and the project scope between message 2 and
    // message 3; the registered session must carry the *new* counters.
    host.authority.advanceGrantRevision(forDevice: SessionFixtures.deviceID)
    host.authority.advanceAuthorizedViewEpoch(forDevice: SessionFixtures.deviceID)

    let authenticated = try await host.coordinator.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offer, request: request),
      connectionID: SessionFixtures.connectionID
    )
    XCTAssertEqual(authenticated.session.grantRevision, 8)
    XCTAssertEqual(authenticated.session.authorizedViewEpoch, 4)
    _ = try await host.coordinator.validate(authenticated.session.record.identity)
  }

  func testHostSignsExactlyTheTranscriptItOffers() async throws {
    let host = try makeHost()
    let request = try SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)
    let transcript = try SessionTranscript(
      sessionID: offer.response.sessionID,
      deviceID: request.deviceID,
      selection: offer.response.selection,
      deviceEphemeralPublicKey: request.deviceEphemeralPublicKey,
      deviceNonce: request.deviceNonce,
      hostEphemeralPublicKey: offer.response.hostEphemeralPublicKey,
      hostNonce: offer.response.hostNonce,
      hostTLSSPKIFingerprint: CryptoFixtures.tlsCurrentSPKIFingerprint
    )
    XCTAssertTrue(
      SecureTranscriptSignature.isValid(
        offer.response.transcriptSignature,
        for: transcript.canonicalEncoding(),
        publicKey: CryptoFixtures.hostSigningKey.publicKey
      )
    )
  }

  // MARK: - Replay of message 1 (the primitive this design removes)

  func testAReplayedRequestCannotRegisterASessionOrEvictALiveOne() async throws {
    let host = try makeHost()
    // The attacker records the device's complete handshake off the wire.
    let captured = try SessionFixtures.request()
    let liveOffer = try await host.coordinator.beginAuthentication(
      request: captured, connectionID: SessionFixtures.connectionID)
    let capturedConfirmation = try SessionFixtures.confirmation(
      for: liveOffer, request: captured)
    let live = try await host.coordinator.completeAuthentication(
      confirmation: capturedConfirmation, connectionID: SessionFixtures.connectionID)
    let liveIdentity = live.session.record.identity

    // It replays message 1 on its own connection. The host answers — the
    // signature really is the device's — and commits nothing.
    let replayOffer = try await host.coordinator.beginAuthentication(
      request: captured, connectionID: SessionFixtures.otherConnectionID)
    XCTAssertNotEqual(replayOffer.response.sessionID, liveIdentity.sessionID)
    XCTAssertEqual(host.store.state().sessions.count, 1)
    XCTAssertEqual(host.store.state().sessions[SessionFixtures.deviceID]?.identity, liveIdentity)

    // Replaying the captured message 3 fails: it was signed over the live
    // session's transcript, and this handshake has fresh host contributions.
    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.completeAuthentication(
        confirmation: capturedConfirmation, connectionID: SessionFixtures.otherConnectionID)
    }
    // Re-labelling it with the new session ID does not help either: the
    // signature must cover the new transcript, which needs the device key.
    let replayOffer2 = try await host.coordinator.beginAuthentication(
      request: captured, connectionID: SessionFixtures.otherConnectionID)
    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.completeAuthentication(
        confirmation: try SecureSessionAuthConfirmation(
          sessionID: replayOffer2.response.sessionID,
          deviceID: SessionFixtures.deviceID,
          transcriptSignature: capturedConfirmation.transcriptSignature
        ),
        connectionID: SessionFixtures.otherConnectionID
      )
    }

    // The live session is untouched throughout.
    XCTAssertEqual(host.store.state().sessions.count, 1)
    XCTAssertEqual(host.store.state().sessions[SessionFixtures.deviceID]?.identity, liveIdentity)
    _ = try await host.coordinator.validate(liveIdentity)
  }

  func testAReplayedRequestCreatesNothingAfterCloseInvalidateOrGenerationAdvance() async throws {
    let host = try makeHost()
    let captured = try SessionFixtures.request()
    let live = try await handshake(host, request: captured)

    for stage in ["close", "invalidate", "advance"] {
      switch stage {
      case "close": _ = await host.coordinator.close(live.session.record.identity)
      case "invalidate":
        _ = await host.coordinator.invalidateSessions(forDevice: SessionFixtures.deviceID)
      default: _ = await host.coordinator.advanceAuthenticationGeneration()
      }
      _ = try await host.coordinator.beginAuthentication(
        request: captured, connectionID: SessionFixtures.otherConnectionID)
      XCTAssertTrue(host.store.state().sessions.isEmpty, "stage \(stage)")
      await assertFails(.authenticationFailed) {
        _ = try await host.coordinator.completeAuthentication(
          confirmation: try SecureSessionAuthConfirmation(
            sessionID: UUID(),
            deviceID: SessionFixtures.deviceID,
            transcriptSignature: Data(repeating: 0x11, count: 64)
          ),
          connectionID: SessionFixtures.otherConnectionID
        )
      }
      XCTAssertTrue(host.store.state().sessions.isEmpty, "stage \(stage)")
    }
  }

  // MARK: - Collapsed pre-authentication rejection

  func testEveryPreAuthenticationRejectionIsIndistinguishable() async throws {
    let host = try makeHost()
    var observed: [SessionClosedReason] = []

    // Unknown device.
    observed.append(
      await captureFailure {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(deviceID: SessionFixtures.secondDeviceID),
          connectionID: SessionFixtures.connectionID)
      })
    // Revoked grant.
    host.authority.setLiveness(.revoked, forDevice: SessionFixtures.deviceID)
    observed.append(
      await captureFailure {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(), connectionID: SessionFixtures.connectionID)
      })
    // Expired grant.
    host.authority.setLiveness(.expired, forDevice: SessionFixtures.deviceID)
    observed.append(
      await captureFailure {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(), connectionID: SessionFixtures.connectionID)
      })
    // Unavailable authority.
    host.authority.setLiveness(.live, forDevice: SessionFixtures.deviceID)
    host.authority.setUnavailable(true)
    observed.append(
      await captureFailure {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(), connectionID: SessionFixtures.connectionID)
      })
    // Bad device signature.
    host.authority.setUnavailable(false)
    observed.append(
      await captureFailure {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(signingKey: CryptoFixtures.tlsCurrentKey),
          connectionID: SessionFixtures.connectionID)
      })
    // Rejected selection.
    observed.append(
      await captureFailure {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(
            selection: CryptoFixtures.reducedFeatureSelection()),
          connectionID: SessionFixtures.connectionID)
      })

    XCTAssertEqual(observed.count, 6)
    XCTAssertEqual(Set(observed), [.authenticationFailed])
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  func testHandshakeCloseCodeIsTheSameWhateverTheInternalReasonWas() {
    for reason in SessionClosedReason.allCases {
      XCTAssertEqual(reason.closeReason(in: .handshake), .authenticationFailed)
    }
    XCTAssertEqual(
      SessionClosedReason.deviceRevoked.closeReason(in: .authenticatedSession), .deviceRevoked)
    XCTAssertEqual(
      SessionClosedReason.grantExpired.closeReason(in: .authenticatedSession), .grantExpired)
    XCTAssertEqual(
      SessionClosedReason.sessionExpired.closeReason(in: .authenticatedSession), .grantExpired)
    XCTAssertEqual(
      SessionClosedReason.sessionSuperseded.closeReason(in: .authenticatedSession),
      .sessionReplaced)
    XCTAssertEqual(
      SessionClosedReason.authorizationChanged.closeReason(in: .authenticatedSession),
      .authorizationChanged)
    XCTAssertEqual(
      SessionClosedReason.generationStale.closeReason(in: .authenticatedSession),
      .authorizationChanged)
    for reason in SessionClosedReason.allCases {
      XCTAssertFalse(reason.rawValue.isEmpty)
      XCTAssertTrue(
        SecureCloseReason.allCases.contains(reason.closeReason(in: .authenticatedSession)))
    }
  }

  private func captureFailure(_ body: () async throws -> Void) async -> SessionClosedReason {
    do {
      try await body()
      XCTFail("expected a closed failure")
      return .authenticationFailed
    } catch {
      return (error as? SessionClosedReason) ?? .authenticationFailed
    }
  }

  // MARK: - Exact negotiation

  func testSelectionDowngradeFutureMinorAndForeignMajorAreRejected() async throws {
    let host = try makeHost()
    for selection in [
      try CryptoFixtures.reducedFeatureSelection(),
      try CryptoFixtures.alternateMinorSelection(),
      try CryptoFixtures.alternateMajorSelection(),
    ] {
      await assertFails(.authenticationFailed) {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(selection: selection),
          connectionID: SessionFixtures.connectionID)
      }
    }
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  func testPhaseTwoNegotiatesNoApprovalFeature() throws {
    let required = try SessionPolicy.requiredSelection()
    XCTAssertEqual(required.features, SecureProtocolNegotiation.supportedFeatures)
    XCTAssertEqual(required.features, Set(SecureProtocolFeature.allCases))
    XCTAssertEqual(required.features.count, 3)
    for feature in SecureProtocolFeature.allCases {
      XCTAssertFalse(feature.rawValue.lowercased().contains("approv"))
    }
    let json = Data(#"{"major":1,"minor":1,"features":["approval-v1"]}"#.utf8)
    XCTAssertThrowsError(try JSONDecoder().decode(SecureProtocolSelection.self, from: json))
  }

  func testSelectionSignedByTheDeviceMustMatchTheSelectionItSent() async throws {
    let host = try makeHost()
    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.beginAuthentication(
        request: SessionFixtures.request(
          signedSelection: CryptoFixtures.reducedFeatureSelection()),
        connectionID: SessionFixtures.connectionID)
    }
  }

  // MARK: - Device proof

  func testInvalidRequestSignaturesAndKeysAreRejected() async throws {
    let host = try makeHost()
    let rejected: [SecureSessionAuthRequest] = [
      try SessionFixtures.request(signingKey: CryptoFixtures.tlsCurrentKey),
      try SessionFixtures.request(tamperSignature: { CryptoFixtures.mutated($0, at: 17) }),
      try SessionFixtures.request(signedHostID: CryptoFixtures.otherUUID),
      try SessionFixtures.request(deviceEphemeralPublicKey: Data(repeating: 0x04, count: 65)),
    ]
    for request in rejected {
      await assertFails(.authenticationFailed) {
        _ = try await host.coordinator.beginAuthentication(
          request: request, connectionID: SessionFixtures.connectionID)
      }
    }
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  func testConfirmationMustMatchTheOfferAndBeSignedByTheDevice() async throws {
    /// Each case gets its own fresh handshake, so the only thing wrong with
    /// the confirmation is the field the case mutates.
    func mutate(
      _ label: String,
      _ build: (HostSessionOffer, SecureSessionAuthRequest) throws
        -> SecureSessionAuthConfirmation
    ) async throws {
      let host = try makeHost()
      let request = try SessionFixtures.request()
      let offer = try await host.coordinator.beginAuthentication(
        request: request, connectionID: SessionFixtures.connectionID)
      let confirmation = try build(offer, request)
      await assertFails(.authenticationFailed) {
        _ = try await host.coordinator.completeAuthentication(
          confirmation: confirmation, connectionID: SessionFixtures.connectionID)
      }
      XCTAssertTrue(host.store.state().sessions.isEmpty, label)
    }

    try await mutate("wrong signer") { offer, request in
      try SessionFixtures.confirmation(
        for: offer, request: request, signingKey: CryptoFixtures.tlsCurrentKey)
    }
    try await mutate("tampered signature") { offer, request in
      try SessionFixtures.confirmation(
        for: offer, request: request, tamperSignature: { CryptoFixtures.mutated($0, at: 5) })
    }
    try await mutate("wrong session") { offer, request in
      try SessionFixtures.confirmation(
        for: offer, request: request, sessionID: CryptoFixtures.otherUUID)
    }
    try await mutate("wrong device") { offer, request in
      try SessionFixtures.confirmation(
        for: offer, request: request, deviceID: SessionFixtures.secondDeviceID)
    }
    try await mutate("foreign TLS binding") { offer, request in
      try SessionFixtures.confirmation(
        for: offer, request: request, tlsSPKIFingerprint: CryptoFixtures.tlsNextSPKIFingerprint)
    }
  }

  func testConfirmationWithoutAnOfferOrOnAnotherConnectionIsRejected() async throws {
    let host = try makeHost()
    let request = try SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)
    let confirmation = try SessionFixtures.confirmation(for: offer, request: request)

    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.completeAuthentication(
        confirmation: confirmation, connectionID: SessionFixtures.otherConnectionID)
    }
    XCTAssertTrue(host.store.state().sessions.isEmpty)

    // The right connection still works, and the handshake is single-use.
    _ = try await host.coordinator.completeAuthentication(
      confirmation: confirmation, connectionID: SessionFixtures.connectionID)
    XCTAssertEqual(host.store.state().sessions.count, 1)
    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.completeAuthentication(
        confirmation: confirmation, connectionID: SessionFixtures.connectionID)
    }
    XCTAssertEqual(host.store.state().sessions.count, 1)
  }

  func testAbandonedHandshakesExpireOnTheMonotonicClock() async throws {
    let host = try makeHost()
    let request = try SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)

    host.clock.set(SessionFixtures.monotonicOrigin + SessionPolicy.handshakeCompletionSeconds)
    let expired = await host.coordinator.pendingHandshakeCount()
    XCTAssertEqual(expired, 0)
    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.completeAuthentication(
        confirmation: SessionFixtures.confirmation(for: offer, request: request),
        connectionID: SessionFixtures.connectionID)
    }
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  func testAbandonHandshakeDropsPendingState() async throws {
    let host = try makeHost()
    let request = try SessionFixtures.request()
    let offer = try await host.coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)
    await host.coordinator.abandonHandshake(connectionID: SessionFixtures.connectionID)

    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.completeAuthentication(
        confirmation: SessionFixtures.confirmation(for: offer, request: request),
        connectionID: SessionFixtures.connectionID)
    }
  }

  // MARK: - Host-side failures leave nothing behind

  func testHostSignerFailuresFailClosedAndRegisterNothing() async throws {
    for signer in [FailingSessionSigner() as any SessionStatementSigner, ShortSessionSigner()] {
      let host = try makeHost(signer: signer)
      await assertFails(.authenticationFailed) {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(), connectionID: SessionFixtures.connectionID)
      }
      XCTAssertTrue(host.store.state().sessions.isEmpty)
    }
  }

  func testEntropyFailuresFailClosedAndRegisterNothing() async throws {
    for random in [
      ScriptedRandomSource(values: [], failure: true),
      ScriptedRandomSource(values: [], truncateTo: 8),
    ] {
      let host = try makeHost(random: random)
      await assertFails(.authenticationFailed) {
        _ = try await host.coordinator.beginAuthentication(
          request: SessionFixtures.request(), connectionID: SessionFixtures.connectionID)
      }
      XCTAssertTrue(host.store.state().sessions.isEmpty)
    }
  }

  // MARK: - One active session per device

  func testReauthenticationReplacesAndReturnsTheSupersededSession() async throws {
    let host = try makeHost()
    let first = try await handshake(host)
    let second = try await handshake(
      host,
      request: try SessionFixtures.request(deviceNonce: nonce(0xA7)),
      connectionID: SessionFixtures.otherConnectionID
    )

    XCTAssertEqual(second.supersededSession, first.session.record.identity)
    XCTAssertNotEqual(
      second.session.record.identity.sessionID, first.session.record.identity.sessionID)
    XCTAssertEqual(host.store.state().sessions.count, 1)
    await assertFails(.sessionSuperseded) {
      _ = try await host.coordinator.validate(first.session.record.identity)
    }
    _ = try await host.coordinator.validate(second.session.record.identity)
  }

  func testTwoCoordinatorsOverOneStoreKeepExactlyOneSession() async throws {
    let authority = try SessionFixtures.authority()
    let store = InMemoryAuthenticatedSessionStore()
    let random = CountingRandomSource()
    let first = try SessionFixtures.coordinator(
      authority: authority, store: store, random: random)
    let second = try SessionFixtures.coordinator(
      authority: authority, store: store, random: random)

    let requestA = try SessionFixtures.request()
    let offerA = try await first.beginAuthentication(
      request: requestA, connectionID: SessionFixtures.connectionID)
    let a = try await first.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offerA, request: requestA),
      connectionID: SessionFixtures.connectionID)

    let requestB = try SessionFixtures.request(deviceNonce: nonce(0x5C))
    let offerB = try await second.beginAuthentication(
      request: requestB, connectionID: SessionFixtures.otherConnectionID)
    let b = try await second.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offerB, request: requestB),
      connectionID: SessionFixtures.otherConnectionID)

    XCTAssertNil(a.supersededSession)
    XCTAssertEqual(b.supersededSession, a.session.record.identity)
    XCTAssertEqual(store.state().sessions.count, 1)
    await assertFails(.sessionSuperseded) {
      _ = try await first.validate(a.session.record.identity)
    }
    _ = try await first.validate(b.session.record.identity)
  }

  func testConcurrentAuthenticationsOverOneStoreKeepExactlyOneSession() async throws {
    let authority = try SessionFixtures.authority()
    let store = InMemoryAuthenticatedSessionStore()
    let random = CountingRandomSource()
    let coordinators = [
      try SessionFixtures.coordinator(authority: authority, store: store, random: random),
      try SessionFixtures.coordinator(authority: authority, store: store, random: random),
    ]
    let requests = try (0..<8).map { index in
      try SessionFixtures.request(deviceNonce: nonce(UInt8(index)))
    }

    let outcomes = await withTaskGroup(
      of: (UUID, UUID?)?.self, returning: [(UUID, UUID?)].self
    ) { group in
      for (index, request) in requests.enumerated() {
        group.addTask {
          let coordinator = coordinators[index % coordinators.count]
          let connectionID = UUID()
          guard
            let offer = try? await coordinator.beginAuthentication(
              request: request, connectionID: connectionID),
            let confirmation = try? SessionFixtures.confirmation(for: offer, request: request),
            let result = try? await coordinator.completeAuthentication(
              confirmation: confirmation, connectionID: connectionID)
          else {
            return nil
          }
          return (result.session.record.identity.sessionID, result.supersededSession?.sessionID)
        }
      }
      var collected: [(UUID, UUID?)] = []
      for await outcome in group {
        if let outcome { collected.append(outcome) }
      }
      return collected
    }

    XCTAssertEqual(outcomes.count, 8)
    XCTAssertEqual(store.state().sessions.count, 1)
    let superseded = Set(outcomes.compactMap(\.1))
    XCTAssertEqual(superseded.count, 7, "each replacement must report a distinct predecessor")
    let survivor = store.state().sessions[SessionFixtures.deviceID]?.identity.sessionID
    XCTAssertNotNil(survivor)
    XCTAssertFalse(superseded.contains(survivor!))
    XCTAssertTrue(outcomes.map(\.0).contains(survivor!))
  }

  // MARK: - Linearization against authorization changes

  func testASessionCannotBeRegisteredAfterAnAuthorizationCommit() async throws {
    // The authority keeps answering with a snapshot captured before the
    // revocation, which is exactly what a handshake suspended across the
    // change would hold.
    let stale = try SessionAuthoritySnapshot(
      deviceID: SessionFixtures.deviceID,
      devicePublicKeyX963: CryptoFixtures.devicePublicKeyX963,
      grantRevision: 7,
      authorizedViewEpoch: 3,
      hostGeneration: 1,
      authorityCommitSequence: 4,
      liveness: .live,
      remainingLifetimeSeconds: nil
    )
    let store = InMemoryAuthenticatedSessionStore()
    let coordinator = try SessionFixtures.coordinator(
      authority: StaleSnapshotAuthority(snapshot: stale), store: store)
    let request = try SessionFixtures.request()
    let offer = try await coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)

    // The Mac commits a tombstone and publishes the new commit sequence.
    let published = await coordinator.publishAuthorityCommit(sequence: 5)
    XCTAssertEqual(published, 5)

    await assertFails(.authenticationFailed) {
      _ = try await coordinator.completeAuthentication(
        confirmation: SessionFixtures.confirmation(for: offer, request: request),
        connectionID: SessionFixtures.connectionID)
    }
    XCTAssertTrue(store.state().sessions.isEmpty)
  }

  func testARevocationCommittedDuringTheAuthorityReadStillWins() async throws {
    let authority = try SessionFixtures.authority()
    let hooked = HookedAuthority(base: authority)
    let store = InMemoryAuthenticatedSessionStore()
    let coordinator = try SessionFixtures.coordinator(authority: hooked, store: store)
    let request = try SessionFixtures.request()
    let offer = try await coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)

    // The revocation lands while the commit-time authority read is in flight.
    hooked.onNextRead {
      authority.setLiveness(.revoked, forDevice: SessionFixtures.deviceID)
    }
    await assertFails(.authenticationFailed) {
      _ = try await coordinator.completeAuthentication(
        confirmation: SessionFixtures.confirmation(for: offer, request: request),
        connectionID: SessionFixtures.connectionID)
    }
    XCTAssertTrue(store.state().sessions.isEmpty)
  }

  func testPublishedAuthorityCommitIsMonotonic() async throws {
    let host = try makeHost()
    _ = await host.coordinator.publishAuthorityCommit(sequence: 9)
    let lowered = await host.coordinator.publishAuthorityCommit(sequence: 2)
    XCTAssertEqual(lowered, 9)
    let watermark = await host.coordinator.publishedAuthorityCommit()
    XCTAssertEqual(watermark, 9)
  }

  // MARK: - Authentication generation

  func testGenerationAdvanceInvalidatesEverySessionAndForcesReauthentication() async throws {
    let host = try makeHost(devices: [SessionFixtures.deviceID, SessionFixtures.secondDeviceID])
    let first = try await handshake(host)
    let second = try await handshake(
      host,
      request: try SessionFixtures.request(
        deviceID: SessionFixtures.secondDeviceID, deviceNonce: nonce(0x31)),
      connectionID: SessionFixtures.otherConnectionID
    )

    let advance = await host.coordinator.advanceAuthenticationGeneration()
    XCTAssertFalse(advance.isExhausted)
    XCTAssertEqual(
      Set(advance.invalidated),
      Set([first.session.record.identity, second.session.record.identity]))
    XCTAssertEqual(advance.generation, AuthenticationGeneration(value: 2))
    XCTAssertTrue(host.store.state().sessions.isEmpty)
    await assertFails(.sessionUnknown) {
      _ = try await host.coordinator.validate(first.session.record.identity)
    }

    let fresh = try await handshake(
      host, request: try SessionFixtures.request(deviceNonce: nonce(0x44)))
    XCTAssertEqual(fresh.session.record.generation, AuthenticationGeneration(value: 2))
  }

  func testASessionFromASupersededGenerationIsDeniedAndSwept() async throws {
    let host = try makeHost()
    let established = try await handshake(host)
    // A registry carried across a listener restart: the generation advanced
    // without the record being cleared.
    host.store.mutate { $0.generation = AuthenticationGeneration(value: 9) }

    await assertFails(.generationStale) {
      _ = try await host.coordinator.validate(established.session.record.identity)
    }
    let hidden = await host.coordinator.activeSession(forDevice: SessionFixtures.deviceID)
    XCTAssertNil(hidden)
    let swept = await host.coordinator.sweepInvalidSessions()
    XCTAssertEqual(
      swept,
      [SessionInvalidation(identity: established.session.record.identity, reason: .generationStale)]
    )
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  func testGenerationAdvanceFailsClosedBeforeOverflowAndStillReportsInvalidatedSessions()
    async throws
  {
    XCTAssertEqual(
      try AuthenticationGeneration(value: .max - 1).advanced(),
      AuthenticationGeneration(value: .max))
    XCTAssertThrowsError(try AuthenticationGeneration(value: .max).advanced()) { error in
      XCTAssertEqual(error as? SessionClosedReason, .generationExhausted)
    }

    let store = InMemoryAuthenticatedSessionStore(
      generation: AuthenticationGeneration(value: .max))
    let host = try makeHost(store: store)
    let established = try await handshake(host)
    XCTAssertEqual(established.session.record.generation, AuthenticationGeneration(value: .max))

    let advance = await host.coordinator.advanceAuthenticationGeneration()
    XCTAssertTrue(advance.isExhausted)
    XCTAssertEqual(advance.invalidated, [established.session.record.identity])
    XCTAssertEqual(advance.generation, AuthenticationGeneration(value: .max))
    XCTAssertTrue(host.store.state().sessions.isEmpty)
    XCTAssertTrue(host.store.state().isGenerationExhausted)

    await assertFails(.authenticationFailed) {
      _ = try await host.coordinator.beginAuthentication(
        request: SessionFixtures.request(deviceNonce: nonce(0x77)),
        connectionID: SessionFixtures.connectionID)
    }
    await assertFails(.generationExhausted) {
      _ = try await host.coordinator.validate(established.session.record.identity)
    }
  }

  func testTheGenerationLatchLivesInTheStoreNotTheCoordinator() async throws {
    let authority = try SessionFixtures.authority()
    let store = InMemoryAuthenticatedSessionStore(
      generation: AuthenticationGeneration(value: .max))
    let first = try SessionFixtures.coordinator(authority: authority, store: store)
    _ = await first.advanceAuthenticationGeneration()

    // A brand-new coordinator over the same registry must stay closed.
    let second = try SessionFixtures.coordinator(authority: authority, store: store)
    await assertFails(.authenticationFailed) {
      _ = try await second.beginAuthentication(
        request: SessionFixtures.request(), connectionID: SessionFixtures.connectionID)
    }
    XCTAssertTrue(store.state().sessions.isEmpty)
  }

  // MARK: - Authorization change and expiry

  func testAdvancedAuthorityCountersDenyContinuedUse() async throws {
    for change in ["revision", "view", "hostGeneration"] {
      let host = try makeHost()
      let established = try await handshake(host)
      _ = try await host.coordinator.validate(established.session.record.identity)

      switch change {
      case "revision": host.authority.advanceGrantRevision(forDevice: SessionFixtures.deviceID)
      case "view": host.authority.advanceAuthorizedViewEpoch(forDevice: SessionFixtures.deviceID)
      default: host.authority.advanceHostGeneration()
      }

      await assertFails(.authorizationChanged) {
        _ = try await host.coordinator.validate(established.session.record.identity)
      }
      let swept = await host.coordinator.sweepInvalidSessions()
      XCTAssertEqual(swept.map(\.reason), [.authorizationChanged], "change \(change)")
      XCTAssertTrue(host.store.state().sessions.isEmpty)
    }
  }

  func testSweepReportsRevocationExpiryAndUnknownDevicesAndSparesLiveSessions() async throws {
    let devices = [
      SessionFixtures.deviceID, SessionFixtures.secondDeviceID,
      SessionFixtures.thirdDeviceID, SessionFixtures.fourthDeviceID,
    ]
    let host = try makeHost(devices: devices)
    var identities: [UUID: AuthenticatedSessionIdentity] = [:]
    for (index, device) in devices.enumerated() {
      let established = try await handshake(
        host,
        request: try SessionFixtures.request(deviceID: device, deviceNonce: nonce(UInt8(index))),
        connectionID: UUID()
      )
      identities[device] = established.session.record.identity
    }

    host.authority.setLiveness(.revoked, forDevice: SessionFixtures.deviceID)
    host.authority.setLiveness(.expired, forDevice: SessionFixtures.secondDeviceID)
    host.authority.removeDevice(SessionFixtures.thirdDeviceID)

    let swept = await host.coordinator.sweepInvalidSessions()
    XCTAssertEqual(
      swept,
      [
        SessionInvalidation(
          identity: identities[SessionFixtures.deviceID]!, reason: .deviceRevoked),
        SessionInvalidation(
          identity: identities[SessionFixtures.secondDeviceID]!, reason: .grantExpired),
        SessionInvalidation(
          identity: identities[SessionFixtures.thirdDeviceID]!, reason: .deviceUnknown),
      ]
    )
    XCTAssertEqual(host.store.state().sessions.count, 1)
    _ = try await host.coordinator.validate(identities[SessionFixtures.fourthDeviceID]!)
  }

  func testSweepReportsAnUnavailableAuthority() async throws {
    let host = try makeHost()
    let established = try await handshake(host)
    host.authority.setUnavailable(true)

    let swept = await host.coordinator.sweepInvalidSessions()
    XCTAssertEqual(
      swept,
      [
        SessionInvalidation(
          identity: established.session.record.identity, reason: .authorityUnavailable)
      ]
    )
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  func testSweepRereadsTheGenerationBeforeRemovingAnything() async throws {
    let authority = try SessionFixtures.authority()
    let hooked = HookedAuthority(base: authority)
    let store = InMemoryAuthenticatedSessionStore()
    let clock = TestPairingClock(SessionFixtures.monotonicOrigin)
    let coordinator = try SessionFixtures.coordinator(
      authority: hooked, store: store, monotonicClock: clock)
    let request = try SessionFixtures.request()
    let offer = try await coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)
    _ = try await coordinator.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offer, request: request),
      connectionID: SessionFixtures.connectionID)

    // Make the sweep evaluate a session that a concurrent generation advance
    // removes underneath it; the commit step must not resurrect or
    // mis-remove anything.
    authority.setLiveness(.revoked, forDevice: SessionFixtures.deviceID)
    hooked.onNextRead {
      store.mutate { state in
        state.generation = AuthenticationGeneration(value: 5)
        state.sessions = [:]
      }
    }
    let swept = await coordinator.sweepInvalidSessions()
    XCTAssertTrue(swept.isEmpty)
    XCTAssertTrue(store.state().sessions.isEmpty)
  }

  func testInvalidateSessionsForOneDeviceLeavesOtherDevicesUntouched() async throws {
    let host = try makeHost(devices: [SessionFixtures.deviceID, SessionFixtures.secondDeviceID])
    let first = try await handshake(host)
    let second = try await handshake(
      host,
      request: try SessionFixtures.request(
        deviceID: SessionFixtures.secondDeviceID, deviceNonce: nonce(0x62)),
      connectionID: SessionFixtures.otherConnectionID
    )

    let invalidated = await host.coordinator.invalidateSessions(forDevice: SessionFixtures.deviceID)
    XCTAssertEqual(invalidated, first.session.record.identity)
    let repeated = await host.coordinator.invalidateSessions(forDevice: SessionFixtures.deviceID)
    XCTAssertNil(repeated)
    let remaining = await host.coordinator.activeSessions().map(\.identity)
    XCTAssertEqual(remaining, [second.session.record.identity])
    _ = try await host.coordinator.validate(second.session.record.identity)
  }

  func testCloseRemovesOnlyTheMatchingSession() async throws {
    let host = try makeHost()
    let first = try await handshake(host)
    let second = try await handshake(
      host,
      request: try SessionFixtures.request(deviceNonce: nonce(0x1D)),
      connectionID: SessionFixtures.otherConnectionID
    )

    let staleClose = await host.coordinator.close(first.session.record.identity)
    XCTAssertNil(staleClose)
    XCTAssertEqual(host.store.state().sessions.count, 1)
    let liveClose = await host.coordinator.close(second.session.record.identity)
    XCTAssertEqual(liveClose, second.session.record.identity)
    XCTAssertTrue(host.store.state().sessions.isEmpty)
    await assertFails(.sessionUnknown) {
      _ = try await host.coordinator.validate(second.session.record.identity)
    }
  }

  // MARK: - Active-session expiry on the monotonic clock

  func testActiveSessionExpiresExactlyAtItsMonotonicDeadline() async throws {
    let host = try makeHost(remainingLifetimeSeconds: 60, grantExpiresAtEpochSeconds: 1_800_000_060)
    let established = try await handshake(host)
    XCTAssertEqual(
      established.session.record.expiresAtMonotonicSeconds,
      SessionFixtures.monotonicOrigin + 60)
    // The wall-clock instant is recorded for the Mac's scheduler only.
    XCTAssertEqual(established.session.record.grantExpiresAtEpochSeconds, 1_800_000_060)

    host.clock.set(SessionFixtures.monotonicOrigin + 59)
    _ = try await host.coordinator.validate(established.session.record.identity)
    let earlySweep = await host.coordinator.sweepInvalidSessions()
    XCTAssertTrue(earlySweep.isEmpty)

    host.clock.set(SessionFixtures.monotonicOrigin + 60)
    await assertFails(.sessionExpired) {
      _ = try await host.coordinator.validate(established.session.record.identity)
    }
    let hidden = await host.coordinator.activeSession(forDevice: SessionFixtures.deviceID)
    XCTAssertNil(hidden)
    let swept = await host.coordinator.sweepInvalidSessions()
    XCTAssertEqual(swept.map(\.reason), [.sessionExpired])
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  func testAGrantThatLooksFresherLaterCannotExtendAnActiveSession() async throws {
    let host = try makeHost(remainingLifetimeSeconds: 60)
    let established = try await handshake(host)

    // A backwards wall-clock step would make the Mac report far more grant
    // lifetime remaining; the session's deadline was fixed once, on the
    // monotonic seam, so it still expires on time.
    host.authority.setRemainingLifetimeSeconds(1_000_000, forDevice: SessionFixtures.deviceID)
    host.clock.set(SessionFixtures.monotonicOrigin + 60)
    await assertFails(.sessionExpired) {
      _ = try await host.coordinator.validate(established.session.record.identity)
    }
  }

  func testAnUnrepresentableGrantLifetimeFailsClosed() async throws {
    let host = try makeHost(remainingLifetimeSeconds: .max)
    await assertFails(.authenticationFailed) {
      _ = try await self.handshake(host)
    }
    XCTAssertTrue(host.store.state().sessions.isEmpty)
  }

  // MARK: - Registry reads

  func testActiveSessionReadsApplyLocalGenerationAndExpiryChecks() async throws {
    let host = try makeHost(
      devices: [SessionFixtures.deviceID, SessionFixtures.secondDeviceID],
      remainingLifetimeSeconds: 30)
    let empty = await host.coordinator.activeSessions()
    XCTAssertTrue(empty.isEmpty)

    let established = try await handshake(host)
    let record = await host.coordinator.activeSession(forDevice: SessionFixtures.deviceID)
    XCTAssertEqual(record, established.session.record)
    let other = await host.coordinator.activeSession(forDevice: SessionFixtures.secondDeviceID)
    XCTAssertNil(other)

    host.clock.set(SessionFixtures.monotonicOrigin + 30)
    let expired = await host.coordinator.activeSession(forDevice: SessionFixtures.deviceID)
    XCTAssertNil(expired)
    let listed = await host.coordinator.activeSessions()
    XCTAssertTrue(listed.isEmpty)
    // The record is still registered until something sweeps or closes it.
    XCTAssertEqual(host.store.state().sessions.count, 1)
  }

  func testValidateRefusesASessionSupersededWhileTheAuthorityReadWasInFlight() async throws {
    let authority = try SessionFixtures.authority()
    let hooked = HookedAuthority(base: authority)
    let store = InMemoryAuthenticatedSessionStore()
    let coordinator = try SessionFixtures.coordinator(authority: hooked, store: store)
    let request = try SessionFixtures.request()
    let offer = try await coordinator.beginAuthentication(
      request: request, connectionID: SessionFixtures.connectionID)
    let established = try await coordinator.completeAuthentication(
      confirmation: SessionFixtures.confirmation(for: offer, request: request),
      connectionID: SessionFixtures.connectionID)

    // A concurrent reauthentication commits while `validate` is suspended on
    // the authority read; the post-read re-check must catch it.
    let replacement = AuthenticatedSessionIdentity(
      sessionID: UUID(), connectionID: SessionFixtures.otherConnectionID,
      deviceID: SessionFixtures.deviceID)
    hooked.onNextRead {
      store.mutate { state in
        guard let current = state.sessions[SessionFixtures.deviceID] else { return }
        state.sessions[SessionFixtures.deviceID] = AuthenticatedSessionRecord(
          identity: replacement,
          generation: current.generation,
          grantRevision: current.grantRevision,
          authorizedViewEpoch: current.authorizedViewEpoch,
          hostGeneration: current.hostGeneration,
          authorityCommitSequence: current.authorityCommitSequence,
          establishedAtMonotonicSeconds: current.establishedAtMonotonicSeconds,
          expiresAtMonotonicSeconds: current.expiresAtMonotonicSeconds,
          grantExpiresAtEpochSeconds: current.grantExpiresAtEpochSeconds,
          requestBinding: current.requestBinding
        )
      }
    }
    await assertFails(.sessionSuperseded) {
      _ = try await coordinator.validate(established.session.record.identity)
    }
  }

  func testSnapshotRejectsAnInvalidDeviceKey() {
    XCTAssertThrowsError(
      try SessionAuthoritySnapshot(
        deviceID: SessionFixtures.deviceID,
        devicePublicKeyX963: Data(repeating: 0x04, count: 64),
        grantRevision: 1,
        authorizedViewEpoch: 1,
        hostGeneration: 1,
        authorityCommitSequence: 1,
        liveness: .live,
        remainingLifetimeSeconds: nil
      )
    ) { error in
      XCTAssertEqual(error as? SessionClosedReason, .deviceKeyInvalid)
    }
  }
}
