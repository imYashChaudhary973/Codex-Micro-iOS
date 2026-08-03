import CompanionCrypto
import CompanionProtocol
import Crypto
import Foundation
import MacBridgeCore
import MacBridgeServer
import Security
import X509
import XCTest

@testable import CodexMicroBridge

/// Pairing over a **real socket**, through the whole stack.
///
/// Every other pairing test drives the state machines directly. This one binds
/// a real `HardenedWSSListener`, completes a real TLS 1.3 handshake against a
/// pinned SPKI, performs the real HTTP upgrade, exchanges real handshake
/// envelopes as WebSocket binary frames, and ends with a real grant in the
/// Mac's authority.
///
/// It is the closest thing to the physical acceptance case that runs without a
/// phone, and it exists because everything up to this point was proven one
/// component at a time. The composition-root defect earlier in Step 2.14 —
/// where the listener silently served denying handlers — is exactly the class
/// of problem that only a test like this catches.
///
/// **This is loopback evidence, not physical-device proof.** It binds
/// `127.0.0.1` and speaks to itself.
final class PairingEndToEndTests: XCTestCase {

  /// The whole pairing choreography over the wire, ending in a stored grant.
  func testAPhonePairsOverARealSocketAndTheMacStoresTheGrant() async throws {
    let world = try await World.start()
    defer { Task { try? await world.listener.stop() } }

    // 1. The Mac opens a session and publishes its QR.
    let payload = try await world.coordinator.createSession(
      endpointOrigin: try PairingEndpointOrigin(
        "wss://\(world.endpoint.host):\(world.endpoint.port)"),
      selection: Self.selection,
      tlsSPKIFingerprint: world.endpoint.spkiFingerprint
    )

    // The QR must name the key the listener is actually serving, or the phone
    // would pin a fingerprint the Mac cannot present.
    XCTAssertEqual(payload.tlsSPKIFingerprint, world.tlsFingerprint)

    // 2. The phone scans it and sends its pairing request over the pinned
    //    socket. The client refuses any server whose SPKI differs.
    let deviceKey = P256.Signing.PrivateKey()
    let device = PairingDeviceEndpoint(
      identity: try PairingDeviceIdentity(
        deviceID: Self.deviceID,
        publicKeyX963: deviceKey.publicKey.x963Representation,
        signer: RawTranscriptSigner(key: deviceKey)
      ))
    let attempt = try device.beginPairing(
      with: BridgePairingQR.payload(
        fromScanned: BridgePairingQR.text(for: payload))!)

    let client = PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: world.tlsFingerprint, deadline: .seconds(10))
    let url = try XCTUnwrap(PinnedProbeWebSocketClient.url(for: world.endpoint))

    // The whole handshake runs on ONE connection. The host binds an in-flight
    // pairing to the transport connection it arrived on, and the phone's own
    // client holds a single socket for the same reason.
    try await client.withConnection(url: url) { connection in
      let requestEnvelope = try ListenerHandshakeEnvelope(
        kind: .pairingRequest, payload: try JSONEncoder().encode(attempt.request))
      try await connection.send(try requestEnvelope.encoded())
      let reply = try ListenerHandshakeEnvelope.decode(try await connection.receive())
      XCTAssertEqual(reply.kind, .pairingResponse)

      // 3. The phone verifies the host's reply against the fingerprint the QR
      //    carried, then derives its own phrase.
      let response = try JSONDecoder().decode(
        SecurePairingResponse.self, from: reply.payload)
      let verification = try attempt.verifyHostResponse(response)

      // 4. The phrase reached the Mac's screen through the observer seam.
      //    This is the fact the handler used to discard.
      let onScreen = await MainActor.run { world.model.pendingWords }
      XCTAssertEqual(
        onScreen, verification.verificationPhrase.displayWords,
        "the Mac and the phone showed different words")

      // 5. Both users confirm.
      let pendingID = await MainActor.run { world.model.pendingPairingSessionID }
      XCTAssertEqual(pendingID, payload.pairingSessionID)
      _ = try await world.coordinator.confirmVerificationPhrase(
        pairingSessionID: payload.pairingSessionID,
        phrase: verification.verificationPhrase
      )
      let confirmation = try verification.confirmLocally(
        matching: verification.verificationPhrase)
      let confirmEnvelope = try ListenerHandshakeEnvelope(
        kind: .pairingConfirmation, payload: try JSONEncoder().encode(confirmation))
      try await connection.send(try confirmEnvelope.encoded())
      self.pairedDeviceKey = deviceKey.publicKey.x963Representation
    }

    // 6. The Mac stored the grant. Without this the phone would reconnect and
    //    be refused as an unknown device.
    try await waitUntilPaired(world.model)
    let stored = try await world.authority.authoritativeGrant(deviceID: Self.deviceID)
    XCTAssertEqual(stored.devicePublicKey, pairedDeviceKey)
    XCTAssertEqual(stored.capabilities, [.view])
    XCTAssertTrue(stored.permittedProjectIDs.isEmpty)
    XCTAssertEqual(stored.actionProfileCeiling, .observe)

    try await world.listener.stop()
  }

  /// A client pinning the wrong SPKI must fail at TLS, before any pairing byte
  /// moves. This is the property that makes a machine-in-the-middle on the
  /// same network a connection failure rather than a silent interception.
  func testAWrongPinFailsBeforeAnyPairingMessageIsSeen() async throws {
    let world = try await World.start()
    defer { Task { try? await world.listener.stop() } }

    let payload = try await world.coordinator.createSession(
      endpointOrigin: try PairingEndpointOrigin(
        "wss://\(world.endpoint.host):\(world.endpoint.port)"),
      selection: Self.selection,
      tlsSPKIFingerprint: world.endpoint.spkiFingerprint
    )
    let client = PinnedProbeWebSocketClient(
      expectedSPKIFingerprint: Data(repeating: 0xAB, count: 32), deadline: .seconds(5))
    let url = try XCTUnwrap(PinnedProbeWebSocketClient.url(for: world.endpoint))

    do {
      _ = try await client.exchange(
        url: url, message: try HandshakeFixture.pairingRequest())
      XCTFail("a wrong pin completed a pairing exchange")
    } catch {
      // Any refusal is correct; what matters is that nothing was paired.
    }

    let state = await MainActor.run { world.model.state }
    XCTAssertEqual(state, .idle, "a refused connection moved the pairing screen")
    let lifecycle = await world.coordinator.lifecycle(of: payload.pairingSessionID)
    XCTAssertEqual(lifecycle, .available, "a refused connection consumed the secret")

    try await world.listener.stop()
  }

  // MARK: - Helpers

  /// Captured inside the connection closure so the assertions after it can
  /// still name the key that actually paired.
  private var pairedDeviceKey = Data()

  static let selection = try! SecureProtocolSelection(
    major: 1, minor: 1, features: [.observeSync])
  static let deviceID = UUID(uuidString: "ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB")!

  /// Polls the pairing model until the grant is recorded.
  ///
  /// The confirmation crosses a socket and the grant write happens on the
  /// observer's task, so the completion is genuinely asynchronous with respect
  /// to the send. Polling with a real sleep rather than spinning is what keeps
  /// this stable under full-suite load — the same lesson Step 2.13 recorded
  /// about the embedded-channel helper.
  private func waitUntilPaired(
    _ model: BridgePairingModel,
    timeout: Duration = .seconds(5)
  ) async throws {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
      let state = await MainActor.run { model.state }
      if case .paired = state { return }
      if case .failed(let reason) = state {
        XCTFail("pairing failed: \(reason)")
        return
      }
      try await Task.sleep(for: .milliseconds(25))
    }
    let final = await MainActor.run { model.state }
    XCTFail("pairing did not complete; ended at \(final)")
  }

  /// A bound listener wired exactly the way the app wires one.
  private struct World {
    let listener: HardenedWSSListener
    let endpoint: ListenerEndpoint
    let tlsFingerprint: Data
    let coordinator: PairingCoordinator
    let authority: DeviceGrantAuthority
    let model: BridgePairingModel

    static func start() async throws -> World {
      let identityStore = BridgeIdentityStore(
        backend: E2EIdentityBackend(), resetPolicy: { false })
      let hostSigner = try EnclaveHostStatementSigner(
        identity: try identityStore.create(role: .host))
      let coordinator = try PairingCoordinator(
        hostID: UUID(uuidString: "BCBCBCBC-BCBC-BCBC-BCBC-BCBCBCBCBCBC")!,
        hostPublicKeyX963: hostSigner.hostPublicKeyX963,
        signer: hostSigner
      )
      let authority = DeviceGrantAuthority(
        storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
      let model = await BridgePairingModel()
      let observer = BridgePairingObserver(
        model: model, recorder: PairingGrantRecorder(authority: authority))

      let sessions = try SessionCoordinator(
        hostID: UUID(uuidString: "CDCDCDCD-CDCD-CDCD-CDCD-CDCDCDCDCDCD")!,
        hostTLSSPKIFingerprint: Data(repeating: 0x77, count: 32),
        authority: GrantAuthoritySessionAuthority(authority: authority, clock: { 1_000_000 }),
        signer: hostSigner,
        store: InMemoryAuthenticatedSessionStore()
      )

      let (servingIdentity, fingerprint) = try E2ETLSIdentity.make()
      let configuration = ListenerConfiguration.testOnlyEnabled(
        binding: try ListenerInterfaceBinding.testOnlyLoopback(),
        handshake: CoordinatorListenerHandshakeHandler(
          pairing: coordinator, session: sessions, observer: observer)
      )
      let listener = HardenedWSSListener(
        configuration: configuration,
        prerequisites: ListenerPrerequisites(
          identity: StaticTLSProvider(identity: servingIdentity),
          grantAuthority: BridgeGrantAuthorityProbe(authority: authority),
          policy: BridgeCapabilityPolicyProbe(),
          codex: AlwaysSupportedCodex()
        )
      )
      let endpoint = try await listener.start()
      return World(
        listener: listener,
        endpoint: endpoint,
        tlsFingerprint: fingerprint,
        coordinator: coordinator,
        authority: authority,
        model: model
      )
    }
  }
}

// MARK: - Deterministic doubles

private struct StaticTLSProvider: ListenerTLSIdentityProviding {
  let identity: ListenerServingIdentity
  func servingIdentity() async throws -> ListenerServingIdentity { identity }
}

private struct AlwaysSupportedCodex: ListenerCodexSupportProbing {
  func assertCodexSupported() async throws {}
}

private struct RawTranscriptSigner: PairingTranscriptSigner {
  let key: P256.Signing.PrivateKey
  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try key.signature(for: canonicalBytes).rawRepresentation
  }
}

private enum HandshakeFixture {
  static func pairingRequest() throws -> Data {
    try ListenerHandshakeEnvelope(
      kind: .pairingRequest, payload: Data(repeating: 0x01, count: 32)
    ).encoded()
  }
}

/// An ephemeral, non-persistent TLS identity for the loopback listener.
///
/// A Secure Enclave key needs an entitled signed host, which a unit test is
/// not, so this uses a non-persistent `SecKey` behind the same serving type.
/// The TLS handshake it produces is real.
private enum E2ETLSIdentity {
  static func make() throws -> (ListenerServingIdentity, Data) {
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
      kSecAttrIsPermanent: false,
    ]
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw BridgeCertificateError.assemblyFailed
    }
    let signer = try Certificate.PrivateKey(secKey)
    let name = try DistinguishedName {
      CommonName(BridgeCertificateProfile.subjectCommonName)
    }
    let extensions = try Certificate.Extensions {
      Critical(BasicConstraints.notCertificateAuthority)
      Critical(KeyUsage(digitalSignature: true))
      try ExtendedKeyUsage([.serverAuth])
      SubjectAlternativeNames([
        .dnsName(BridgeCertificateProfile.subjectAlternativeDNSName)
      ])
    }
    let now = Date()
    let certificate = try Certificate(
      version: .v3,
      serialNumber: Certificate.SerialNumber(),
      publicKey: signer.publicKey,
      notValidBefore: now.addingTimeInterval(-60),
      notValidAfter: now.addingTimeInterval(3_600),
      issuer: name,
      subject: name,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: extensions,
      issuerPrivateKey: signer
    )
    let secCertificate = try SecCertificate.makeWithCertificate(certificate)
    guard let secIdentity = SecIdentityCreate(nil, secCertificate, secKey) else {
      throw BridgeCertificateError.assemblyFailed
    }
    let point = Data(certificate.publicKey.subjectPublicKeyInfoBytes)
    let spkiDER = try SPKIFingerprint.subjectPublicKeyInfoDER(x963PublicKey: point)
    let fingerprint = Data(SHA256.hash(data: spkiDER))
    return (
      ListenerServingIdentity.testOnlyAssembled(
        secIdentity: secIdentity, spkiFingerprint: fingerprint),
      fingerprint
    )
  }
}

/// A CryptoKit-backed identity backend for the host signing key.
private final class E2EIdentityBackend: SecureIdentityBackend {
  private final class Key: SecureIdentityKey {
    let key = P256.Signing.PrivateKey()
    func publicKeyX963() throws -> Data { key.publicKey.x963Representation }
    func signRaw(_ message: Data) throws -> Data {
      try key.signature(for: message).rawRepresentation
    }
    func validateRequiredAttributes() throws {}
    func assertNonExportable() throws {}
    func certificateSigner() throws -> Certificate.PrivateKey { Certificate.PrivateKey(key) }
  }

  private var claims: Set<BridgeIdentityRole> = []
  private var keys: [BridgeIdentityRole: [Key]] = [:]

  func insertClaim(for role: BridgeIdentityRole) throws -> BridgeClaimInsertion {
    claims.insert(role).inserted ? .inserted : .alreadyPresent
  }
  func claimCount(for role: BridgeIdentityRole) throws -> Int { claims.contains(role) ? 1 : 0 }
  func removeClaim(for role: BridgeIdentityRole) throws { claims.remove(role) }
  func createKey(for role: BridgeIdentityRole) throws -> any SecureIdentityKey {
    let key = Key()
    keys[role, default: []].append(key)
    return key
  }
  func existingKeys(for role: BridgeIdentityRole) throws -> [any SecureIdentityKey] {
    keys[role] ?? []
  }
  func deleteKey(_ key: any SecureIdentityKey, for role: BridgeIdentityRole) throws {
    keys[role] = (keys[role] ?? []).filter { $0 !== (key as? Key) }
  }
  func deleteAllKeys(for role: BridgeIdentityRole) throws { keys[role] = [] }
  func withExclusiveCreation<T>(_ body: () throws -> T) rethrows -> T { try body() }
}
