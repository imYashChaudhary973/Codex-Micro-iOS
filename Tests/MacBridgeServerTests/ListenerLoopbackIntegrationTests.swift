import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeServer

/// Loopback integration through the real stack: Network.framework TLS 1.3,
/// the exact HTTP upgrade, the WebSocket frame policy, the pre-authentication
/// allowlist, and the SPKI-pinned client.
///
/// This is loopback/Mac-only evidence. It is never physical-device proof.
final class ListenerLoopbackIntegrationTests: XCTestCase {
  private struct Harness {
    let listener: HardenedWSSListener
    let endpoint: ListenerEndpoint
    let fingerprint: Data
    let url: URL
  }

  private func start(
    handshake: any ListenerHandshakeHandling,
    ceilings: ListenerCeilings = ListenerCeilings(),
    logger: any ListenerLogging = DiscardingListenerLogger()
  ) async throws -> Harness {
    let (identity, fingerprint) = try EphemeralTLSIdentity.make()
    let configuration = ListenerConfiguration.testOnlyEnabled(
      binding: try ListenerInterfaceBinding.testOnlyLoopback(),
      ceilings: ceilings,
      handshake: handshake,
      logger: logger
    )
    let listener = HardenedWSSListener(
      configuration: configuration,
      prerequisites: .allPassing(identity: identity)
    )
    let endpoint = try await listener.start()
    let url = try XCTUnwrap(PinnedProbeWebSocketClient.url(for: endpoint))
    return Harness(listener: listener, endpoint: endpoint, fingerprint: fingerprint, url: url)
  }

  private func client(
    _ harness: Harness,
    deadline: Duration = .seconds(5)
  ) -> PinnedProbeWebSocketClient {
    PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: harness.fingerprint,
      deadline: deadline
    )
  }

  // MARK: - Pinned round trip

  func testPinnedRoundTripThroughTheRealTLSAndUpgradeStack() async throws {
    let reply = try ListenerHandshakeEnvelope(
      kind: .sessionAuthResponse,
      payload: Data(repeating: 0x5A, count: 48)
    )
    let handler = ScriptedHandshakeHandler(outcomes: [.reply(reply)])
    let harness = try await start(handshake: handler)
    defer { Task { try? await harness.listener.stop() } }

    let request = try HandshakeFixture.envelope(kind: .sessionAuthRequest)
    let response = try await client(harness).exchange(url: harness.url, message: request)
    let decoded = try ListenerHandshakeEnvelope.decode(response)
    XCTAssertEqual(decoded.kind, .sessionAuthResponse)
    XCTAssertEqual(decoded.payload, reply.payload)
    XCTAssertEqual(handler.receivedKinds, [.sessionAuthRequest])
    try await harness.listener.stop()
  }

  func testWrongPinIsSurfacedExactly() async throws {
    let harness = try await start(handshake: ScriptedHandshakeHandler())
    defer { Task { try? await harness.listener.stop() } }

    var wrong = harness.fingerprint
    wrong[0] ^= 0x01
    let mismatched = PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: wrong,
      deadline: .seconds(5)
    )
    do {
      _ = try await mismatched.exchange(url: harness.url, message: Data([0x01, 0x02]))
      XCTFail("a mismatched pin must not complete the handshake")
    } catch {
      XCTAssertEqual(error as? PinnedProbeClientError, .pinMismatch)
    }
    try await harness.listener.stop()
  }

  func testTruncatedPinIsRejected() async throws {
    let harness = try await start(handshake: ScriptedHandshakeHandler())
    defer { Task { try? await harness.listener.stop() } }
    let truncated = PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: harness.fingerprint.dropLast(),
      deadline: .seconds(5)
    )
    do {
      _ = try await truncated.exchange(url: harness.url, message: Data([0x01]))
      XCTFail("a truncated pin must not match")
    } catch {
      XCTAssertEqual(error as? PinnedProbeClientError, .pinMismatch)
    }
    try await harness.listener.stop()
  }

  // MARK: - Zero pre-authentication application disclosure

  func testNonPairedClientReceivesOnlyAClosedReason() async throws {
    let handler = ScriptedHandshakeHandler()
    let harness = try await start(handshake: handler)
    defer { Task { try? await harness.listener.stop() } }

    // An application-shaped message, exactly what an unpaired prober sends.
    let probe = Data(
      #"{"subscriptionID":"00000000-0000-0000-0000-000000000000","resumeCursor":null}"#.utf8)
    let response = try await client(harness).exchange(url: harness.url, message: probe)
    let envelope = try ListenerHandshakeEnvelope.decode(response)
    XCTAssertEqual(envelope.kind, .closeNotice)

    let object = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: envelope.payload) as? [String: Any])
    XCTAssertEqual(Set(object.keys), ["reason"])
    let notice = try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload)
    XCTAssertEqual(notice.reason, ListenerPreAuthAllowlist.collapsedRefusal)
    XCTAssertTrue(handler.receivedKinds.isEmpty, "an application message never reaches a seam")

    // The whole reply, byte for byte, mentions nothing about the bridge.
    let text = String(decoding: response, as: UTF8.self)
    for forbidden in ["thread", "project", "codex", "grant", "journal", "device", "session"] {
      XCTAssertFalse(text.lowercased().contains(forbidden), forbidden)
    }
    try await harness.listener.stop()
  }

  func testUnknownAndRevokedDevicesAreIndistinguishable() async throws {
    // Both answers come from the same collapsed closed reason, so two
    // different device states produce byte-identical transport behaviour.
    let handler = ScriptedHandshakeHandler(repeating: .close(.authenticationFailed))
    let harness = try await start(handshake: handler)
    defer { Task { try? await harness.listener.stop() } }

    var responses: [Data] = []
    for _ in 0..<2 {
      let request = try HandshakeFixture.envelope(kind: .sessionAuthRequest)
      responses.append(try await client(harness).exchange(url: harness.url, message: request))
    }
    XCTAssertEqual(responses[0], responses[1])
    let envelope = try ListenerHandshakeEnvelope.decode(responses[0])
    let notice = try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload)
    XCTAssertEqual(notice.reason, .authenticationFailed)
    try await harness.listener.stop()
  }

  func testUnknownRevokedAndExpiredDevicesAreByteIdenticalOverTheRealCoordinator() async throws {
    let hostKey = P256.Signing.PrivateKey()
    let hostID = UUID()
    let tlsFingerprint = Data(repeating: 0x44, count: SPKIFingerprint.byteCount)
    let authority = InMemorySessionAuthority()
    let coordinator = try SessionCoordinator(
      hostID: hostID,
      hostTLSSPKIFingerprint: tlsFingerprint,
      authority: authority,
      signer: LoopbackSigner(privateKey: hostKey)
    )
    let harness = try await start(
      handshake: CoordinatorListenerHandshakeHandler(pairing: nil, session: coordinator))
    defer { Task { try? await harness.listener.stop() } }

    func requestBytes(deviceID: UUID, key: P256.Signing.PrivateKey) throws -> Data {
      let endpoint = try SessionDeviceEndpoint(
        identity: SessionDeviceIdentity(
          deviceID: deviceID,
          publicKeyX963: key.publicKey.x963Representation,
          signer: LoopbackSigner(privateKey: key)
        ),
        hostID: hostID,
        hostPublicKeyX963: hostKey.publicKey.x963Representation,
        hostTLSSPKIFingerprint: tlsFingerprint
      )
      return try ListenerHandshakeEnvelope(
        kind: .sessionAuthRequest,
        payload: try JSONEncoder().encode(endpoint.beginAuthentication().request)
      ).encoded()
    }

    let unknown = (id: UUID(), key: P256.Signing.PrivateKey())
    let revoked = (id: UUID(), key: P256.Signing.PrivateKey())
    let expired = (id: UUID(), key: P256.Signing.PrivateKey())
    try authority.setDevice(
      deviceID: revoked.id, devicePublicKeyX963: revoked.key.publicKey.x963Representation)
    authority.setLiveness(.revoked, forDevice: revoked.id)
    try authority.setDevice(
      deviceID: expired.id, devicePublicKeyX963: expired.key.publicKey.x963Representation)
    authority.setLiveness(.expired, forDevice: expired.id)

    var replies: [Data] = []
    for device in [unknown, revoked, expired] {
      let request = try requestBytes(deviceID: device.id, key: device.key)
      replies.append(try await client(harness).exchange(url: harness.url, message: request))
    }
    XCTAssertEqual(Set(replies).count, 1, "unknown, revoked, and expired must be indistinguishable")
    let envelope = try ListenerHandshakeEnvelope.decode(try XCTUnwrap(replies.first))
    let notice = try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload)
    XCTAssertEqual(notice.reason, .authenticationFailed)
    let sessions = await coordinator.activeSessions()
    XCTAssertTrue(sessions.isEmpty)
    try await harness.listener.stop()
  }

  func testTLSOptionsBuildFromTheServingIdentity() throws {
    let (identity, fingerprint) = try EphemeralTLSIdentity.make()
    XCTAssertEqual(fingerprint.count, SPKIFingerprint.byteCount)
    XCTAssertEqual(identity.spkiFingerprint, fingerprint)
    XCTAssertNoThrow(try HardenedWSSListener.makeTLSOptions(identity: identity))
  }

  // MARK: - Upgrade policy over the real stack

  func testQueryStringOnTheUpgradePathIsRejected() async throws {
    let harness = try await start(handshake: ScriptedHandshakeHandler())
    defer { Task { try? await harness.listener.stop() } }

    let url = try XCTUnwrap(
      URL(
        string:
          "wss://127.0.0.1:\(harness.endpoint.port)\(ListenerUpgradePolicy.path)?sentinel=1"))
    do {
      _ = try await client(harness, deadline: .seconds(3))
        .exchange(url: url, message: Data([0x01]))
      XCTFail("a query string must be rejected")
    } catch {
      // Expected: the listener closes without upgrading.
    }
    let rejection = await harness.listener.lastUpgradeRejection()
    XCTAssertEqual(rejection, .pathOrQuery)
    try await harness.listener.stop()
  }

  func testWrongPathIsRejected() async throws {
    let harness = try await start(handshake: ScriptedHandshakeHandler())
    defer { Task { try? await harness.listener.stop() } }

    let url = try XCTUnwrap(URL(string: "wss://127.0.0.1:\(harness.endpoint.port)/"))
    do {
      _ = try await client(harness, deadline: .seconds(3))
        .exchange(url: url, message: Data([0x01]))
      XCTFail("a foreign path must be rejected")
    } catch {
      // Expected.
    }
    let rejection = await harness.listener.lastUpgradeRejection()
    XCTAssertEqual(rejection, .pathOrQuery)
    try await harness.listener.stop()
  }

  func testPlainNonUpgradeRequestIsBoundedAndDiscloseNothing() async throws {
    let logger = InMemoryListenerLogger()
    let harness = try await start(handshake: ScriptedHandshakeHandler(), logger: logger)
    defer { Task { try? await harness.listener.stop() } }

    let url = try XCTUnwrap(
      URL(string: "https://127.0.0.1:\(harness.endpoint.port)\(ListenerUpgradePolicy.path)"))
    let probe = client(harness, deadline: .seconds(3))

    // A plain GET never reaches the upgrade policy, so it must still be
    // bounded by the pre-upgrade budget and the upgrade deadline.
    do {
      try await probe.probeNonUpgradeRequest(url: url)
    } catch {
      // Expected: the listener answers nothing useful and closes.
    }

    // A body past the pre-upgrade budget is refused rather than streamed for
    // the whole upgrade window.
    let oversized = Data(repeating: 0x41, count: ListenerCeilings.preUpgradeByteCeiling * 4)
    do {
      try await client(harness, deadline: .seconds(3))
        .probeNonUpgradeRequest(url: url, method: "POST", body: oversized)
      XCTFail("an oversized pre-upgrade body must not be accepted")
    } catch {
      // Expected.
    }
    try await harness.listener.stop()

    XCTAssertEqual(logger.count(of: .connectionAuthenticated), 0)
    let codes = Set(ListenerLogCode.allCases.map(\.rawValue))
    for event in logger.events {
      XCTAssertTrue(codes.contains(event.code.rawValue))
    }
  }

  // MARK: - Real authenticated handshake through the coordinator seam

  func testAuthenticatedHandshakeThroughTheRealSessionCoordinator() async throws {
    let hostKey = P256.Signing.PrivateKey()
    let deviceKey = P256.Signing.PrivateKey()
    let hostID = UUID()
    let deviceID = UUID()
    let tlsFingerprint = Data(repeating: 0x33, count: SPKIFingerprint.byteCount)

    let authority = InMemorySessionAuthority()
    try authority.setDevice(
      deviceID: deviceID,
      devicePublicKeyX963: deviceKey.publicKey.x963Representation
    )
    let coordinator = try SessionCoordinator(
      hostID: hostID,
      hostTLSSPKIFingerprint: tlsFingerprint,
      authority: authority,
      signer: LoopbackSigner(privateKey: hostKey)
    )
    let handler = CoordinatorListenerHandshakeHandler(pairing: nil, session: coordinator)
    let harness = try await start(handshake: handler)
    defer { Task { try? await harness.listener.stop() } }

    let endpoint = try SessionDeviceEndpoint(
      identity: SessionDeviceIdentity(
        deviceID: deviceID,
        publicKeyX963: deviceKey.publicKey.x963Representation,
        signer: LoopbackSigner(privateKey: deviceKey)
      ),
      hostID: hostID,
      hostPublicKeyX963: hostKey.publicKey.x963Representation,
      hostTLSSPKIFingerprint: tlsFingerprint
    )
    let attempt = try endpoint.beginAuthentication()
    let messageOne = try ListenerHandshakeEnvelope(
      kind: .sessionAuthRequest,
      payload: try JSONEncoder().encode(attempt.request)
    ).encoded()

    // Messages 1 and 2 are lockstep on one connection; message 3 is not
    // answered, because post-authentication traffic is sealed and belongs
    // to Step 2.8.
    let sessionID: UUID = try await client(harness).withConnection(url: harness.url) { connection in
      try await connection.send(messageOne)
      let replyEnvelope = try ListenerHandshakeEnvelope.decode(try await connection.receive())
      XCTAssertEqual(replyEnvelope.kind, .sessionAuthResponse)
      let response = try JSONDecoder().decode(
        SecureSessionAuthResponse.self, from: replyEnvelope.payload)
      let completion = try attempt.completeAuthentication(with: response)
      let messageThree = try ListenerHandshakeEnvelope(
        kind: .sessionAuthConfirmation,
        payload: try JSONEncoder().encode(completion.confirmation)
      ).encoded()
      try await connection.send(messageThree)
      // Give the host's dispatch a bounded window to commit before the
      // connection is torn down by the enclosing `withConnection`.
      for _ in 0..<50 {
        if await coordinator.activeSession(forDevice: deviceID) != nil { break }
        try await Task.sleep(for: .milliseconds(20))
      }
      return completion.session.sessionID
    }

    // The coordinator registered exactly one session for exactly this device.
    let active = await coordinator.activeSession(forDevice: deviceID)
    XCTAssertNotNil(active)
    XCTAssertEqual(active?.identity.deviceID, deviceID)
    XCTAssertEqual(active?.identity.sessionID, sessionID)
    let snapshot = await harness.listener.snapshot()
    XCTAssertEqual(snapshot.authenticatedChildren, 1)
    try await harness.listener.stop()
  }

  // MARK: - Flood behaviour

  func testUnauthenticatedConnectionFloodIsRefusedByTheCap() async throws {
    let reply = try ListenerHandshakeEnvelope(
      kind: .sessionAuthResponse,
      payload: Data(repeating: 0x11, count: 8)
    )
    let handler = ScriptedHandshakeHandler(repeating: .reply(reply))
    let harness = try await start(handshake: handler)
    defer { Task { try? await harness.listener.stop() } }

    let request = try HandshakeFixture.envelope(kind: .sessionAuthRequest)
    let url = harness.url
    let fingerprint = harness.fingerprint
    let attempts = 10
    let outcomes = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
      for _ in 0..<attempts {
        group.addTask {
          let probe = PinnedProbeWebSocketClient(
            expectedSPKIFingerprint: fingerprint,
            deadline: .seconds(2)
          )
          // Ask for two replies so the connection stays open past the first.
          let result = try? await probe.exchange(
            url: url,
            messages: [request],
            expectedReplies: 2
          )
          return result != nil
        }
      }
      var collected: [Bool] = []
      for await value in group { collected.append(value) }
      return collected
    }

    XCTAssertEqual(outcomes.count, attempts)
    XCTAssertFalse(outcomes.contains(true), "no client receives a second reply")
    let rejection = await harness.listener.lastAdmissionRejection()
    XCTAssertEqual(rejection, .unauthenticatedCapacity)
    try await harness.listener.stop()

    let snapshot = await harness.listener.snapshot()
    XCTAssertEqual(snapshot.phase, .terminated)
    XCTAssertEqual(snapshot.activeChildren, 0)
    XCTAssertTrue(snapshot.groupShutdown)
  }

  // MARK: - Redacted logging

  func testOnlyClosedCodesAndCountsReachTheLogger() async throws {
    let logger = InMemoryListenerLogger()
    let harness = try await start(handshake: ScriptedHandshakeHandler(), logger: logger)
    defer { Task { try? await harness.listener.stop() } }

    let probe = Data(#"{"sentinel":"thread-42/project-alpha"}"#.utf8)
    _ = try? await client(harness, deadline: .seconds(3))
      .exchange(url: harness.url, message: probe)
    try await harness.listener.stop()

    XCTAssertFalse(logger.events.isEmpty)
    let codes = Set(ListenerLogCode.allCases.map(\.rawValue))
    for event in logger.events {
      XCTAssertTrue(codes.contains(event.code.rawValue))
      XCTAssertGreaterThanOrEqual(event.count, 0)
    }
    XCTAssertGreaterThanOrEqual(logger.count(of: .connectionAccepted), 1)
    XCTAssertGreaterThanOrEqual(logger.count(of: .preAuthMessageRejected), 1)
  }
}

/// Long-term signer seam backed by a software key, standing in for the
/// Secure Enclave identity that `swift test` cannot reach.
struct LoopbackSigner: SessionStatementSigner {
  let privateKey: P256.Signing.PrivateKey

  func signSessionStatement(_ canonicalBytes: Data) throws -> Data {
    try privateKey.signature(for: canonicalBytes).rawRepresentation
  }
}
