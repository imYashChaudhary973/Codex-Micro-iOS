import CompanionCrypto
import CompanionProtocol
import Crypto
import Foundation
import MacBridgeCore
import MacBridgeServer
import X509
import XCTest

@testable import CodexMicroBridge

/// The pairing wiring: the two facts the transport learns, and what is done
/// with them.
///
/// Before Step 2.14 the handshake handler computed the verification phrase and
/// dropped it, and dropped the completed proposal. Dual confirmation had no
/// screen and a successful pairing produced no grant, so a paired device
/// reconnected and was refused as unknown. These tests pin both paths.
final class BridgePairingTests: XCTestCase {

  // MARK: - Statement signing

  /// The `.tls` identity serves TLS and must never sign a statement. The role
  /// is enforced here as well as in `TLSRotationAuthority`, so the rule holds
  /// at every place a statement is signed rather than at one of them.
  func testTheSignerRefusesAnIdentityThatIsNotTheHost() throws {
    let store = BridgeIdentityStore(backend: InMemoryIdentityBackend(), resetPolicy: { false })
    let tls = try store.create(role: .tls)

    XCTAssertThrowsError(try EnclaveHostStatementSigner(identity: tls)) { error in
      XCTAssertEqual(
        error as? EnclaveHostStatementSigner.Failure, .wrongIdentityRole(.tls))
    }
  }

  /// Both seams produce a verifiable 64-byte `r||s` signature over the bytes
  /// they were given, and the public key the coordinator will publish comes
  /// from the same identity that signs — so a coordinator cannot be built with
  /// a key that does not match its own signatures.
  func testTheSignerSignsBothStatementKindsVerifiably() throws {
    let store = BridgeIdentityStore(backend: InMemoryIdentityBackend(), resetPolicy: { false })
    let identity = try store.create(role: .host)
    let signer = try EnclaveHostStatementSigner(identity: identity)
    let message = Data("canonical bytes".utf8)

    let pairingSignature = try signer.signPairingTranscript(message)
    let sessionSignature = try signer.signSessionStatement(message)

    XCTAssertEqual(pairingSignature.count, 64)
    XCTAssertEqual(sessionSignature.count, 64)
    XCTAssertEqual(signer.hostPublicKeyX963, identity.publicKeyX963)
    let publicKey = try identity.publicSigningKey()
    for signature in [pairingSignature, sessionSignature] {
      let parsed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
      XCTAssertTrue(publicKey.isValidSignature(parsed, for: message))
    }
  }

  // MARK: - Proposal → grant

  /// Pairing can only ever propose `observe` with no projects, and the stored
  /// grant must not be wider than the proposal. A freshly paired device sees
  /// nothing until the Mac user grants it a project.
  ///
  /// The proposal comes from a **real** pairing run rather than a fabricated
  /// value: `PairedDeviceProposal`'s initializer is internal on purpose, and
  /// widening it so a test could mint one would let the test assert something
  /// pairing never actually produces.
  func testACompletedPairingStoresAnObserveOnlyGrant() async throws {
    let run = try await PairingRun.complete()
    let authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })

    let stored = try await PairingGrantRecorder(authority: authority).record(run.proposal)

    XCTAssertEqual(stored.deviceID, run.deviceID)
    XCTAssertEqual(stored.devicePublicKey, run.devicePublicKey)
    XCTAssertEqual(stored.capabilities, [.view])
    XCTAssertTrue(stored.permittedProjectIDs.isEmpty, "a fresh pairing granted a project")
    XCTAssertEqual(stored.actionProfileCeiling, .observe)
  }

  /// The property the six words exist to establish: both endpoints derive the
  /// same phrase from independently reconstructed transcripts. If these ever
  /// disagreed, the user comparing them would be comparing noise.
  func testBothEndpointsDeriveTheSamePhrase() async throws {
    let run = try await PairingRun.complete()

    XCTAssertEqual(run.hostPhrase, run.devicePhrase)
    XCTAssertEqual(run.hostPhrase.displayWords.count, 6)
    XCTAssertEqual(run.hostPhrase.displayWords, run.devicePhrase.displayWords)
  }

  /// The intent vocabulary maps onto exactly one authoritative capability.
  /// The translation is a total switch, so a new intent case fails to compile
  /// rather than silently falling through to something permissive.
  func testTheCapabilityMappingIsObserveToViewAndNothingElse() {
    XCTAssertEqual(PairingGrantRecorder.capabilities([.observe]), [.view])
    XCTAssertEqual(PairingGrantRecorder.capabilities([]), [])
  }

  /// Re-pairing a device the Mac already holds is the authority's decision.
  /// Silently overwriting would reset a grant revision the phone's session
  /// counters are bound to.
  func testRecordingTheSameDeviceTwiceIsRefused() async throws {
    let authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
    let recorder = PairingGrantRecorder(authority: authority)
    let proposal = try await PairingRun.complete().proposal
    _ = try await recorder.record(proposal)

    do {
      _ = try await recorder.record(proposal)
      XCTFail("a duplicate pairing silently overwrote a grant")
    } catch {}
  }

  // MARK: - The observer

  func testAClaimPutsThePhraseOnScreen() async throws {
    let model = await BridgePairingModel()
    let authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
    let observer = BridgePairingObserver(
      model: model, recorder: PairingGrantRecorder(authority: authority))
    let run = try await PairingRun.complete()

    await observer.pairingClaimed(
      pairingSessionID: run.pairingSessionID, phrase: run.hostPhrase)

    let (pendingID, words) = await MainActor.run {
      (model.pendingPairingSessionID, model.pendingWords)
    }
    XCTAssertEqual(pendingID, run.pairingSessionID)
    XCTAssertEqual(words.count, 6)
    XCTAssertEqual(words, run.hostPhrase.displayWords)
  }

  /// A screen that says "paired" while the Mac holds no grant would send the
  /// user to a phone that is about to be refused as unknown.
  func testAFailedGrantWriteReportsFailedRatherThanPaired() async throws {
    let model = await BridgePairingModel()
    let storage = InMemoryGrantAuthorityStore()
    storage.failLoads(with: .authorityMissing)
    let observer = BridgePairingObserver(
      model: model,
      recorder: PairingGrantRecorder(
        authority: DeviceGrantAuthority(storage: storage, clock: { 1_000_000 }))
    )

    await observer.pairingCompleted(try await PairingRun.complete().proposal)

    let state = await MainActor.run { model.state }
    // The specific authority failure is carried through: "the write failed"
    // and "the authority is unavailable" send the reader to different places.
    XCTAssertEqual(state, .failed(reason: "grantNotStored.authorityUnavailable"))
  }

  // MARK: - The QR payload

  /// The QR carries base64 text because a scanned code comes back as a
  /// `String`; pushing raw canonical bytes through that round-trip corrupts
  /// them.
  func testTheQRTextRoundTripsBackToTheSamePayload() throws {
    let payload = try PairingQRPayload(
      selection: SecureProtocolSelection(major: 1, minor: 1, features: [.observeSync]),
      hostID: UUID(uuidString: "88888888-8888-8888-8888-888888888888")!,
      endpointOrigin: try PairingEndpointOrigin("wss://192.168.1.20:8443"),
      hostIdentityFingerprint: Data(repeating: 0x11, count: 32),
      tlsSPKIFingerprint: Data(repeating: 0x22, count: 32),
      pairingSessionID: UUID(uuidString: "99999999-9999-9999-9999-999999999999")!,
      bootstrapSecret: Data(repeating: 0x33, count: 32),
      expiresAtEpochSeconds: 1_000_300
    )

    let text = BridgePairingQR.text(for: payload)
    let decoded = BridgePairingQR.payload(fromScanned: text)

    XCTAssertEqual(decoded, payload)
  }

  /// Anything that is not one of our codes is simply not one of our codes —
  /// no partial parse, no throw reaching the UI.
  func testAForeignCodeDecodesToNothing() {
    XCTAssertNil(BridgePairingQR.payload(fromScanned: "https://example.com"))
    XCTAssertNil(BridgePairingQR.payload(fromScanned: "not base64 !!!"))
    XCTAssertNil(BridgePairingQR.payload(fromScanned: Data([1, 2, 3]).base64EncodedString()))
  }

  func testTheQRRendersToAnImage() throws {
    let image = try XCTUnwrap(BridgePairingQR.image(for: "hello", scale: 4))
    XCTAssertGreaterThan(image.width, 0)
    XCTAssertEqual(image.width, image.height, "a QR is square")
  }
}

// MARK: - Deterministic doubles

/// One complete pairing, driven through both real state machines.
///
/// This is the closest thing to an end-to-end pairing that runs without a
/// socket: a real ``PairingCoordinator`` on the host side and a real
/// ``PairingDeviceEndpoint`` on the device side, exchanging the actual
/// messages in order. It is what produces a genuine ``PairedDeviceProposal``
/// for the grant tests, and it is what proves the two phrases agree.
private struct PairingRun {
  let pairingSessionID: UUID
  let deviceID: UUID
  let devicePublicKey: Data
  let hostPhrase: SecureShortAuthenticationString
  let devicePhrase: SecureShortAuthenticationString
  let proposal: PairedDeviceProposal

  static func complete() async throws -> PairingRun {
    let store = BridgeIdentityStore(backend: InMemoryIdentityBackend(), resetPolicy: { false })
    let hostIdentity = try store.create(role: .host)
    let hostSigner = try EnclaveHostStatementSigner(identity: hostIdentity)
    let coordinator = try PairingCoordinator(
      hostID: UUID(uuidString: "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD")!,
      hostPublicKeyX963: hostSigner.hostPublicKeyX963,
      signer: hostSigner
    )

    let deviceKey = P256.Signing.PrivateKey()
    let deviceID = UUID(uuidString: "EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE")!
    let device = PairingDeviceEndpoint(
      identity: try PairingDeviceIdentity(
        deviceID: deviceID,
        publicKeyX963: deviceKey.publicKey.x963Representation,
        signer: RawP256TranscriptSigner(key: deviceKey)
      ))

    let selection = try SecureProtocolSelection(major: 1, minor: 1, features: [.observeSync])
    let payload = try await coordinator.createSession(
      endpointOrigin: try PairingEndpointOrigin("wss://192.168.1.20:8443"),
      selection: selection,
      tlsSPKIFingerprint: Data(repeating: 0x22, count: 32)
    )

    // Device scans, host claims, device verifies the host's reply.
    let attempt = try device.beginPairing(with: payload)
    let acceptance = try await coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)

    // Both users confirm. The device signs only for a matching phrase.
    _ = try await coordinator.confirmVerificationPhrase(
      pairingSessionID: payload.pairingSessionID,
      phrase: acceptance.verificationPhrase
    )
    let confirmation = try verification.confirmLocally(
      matching: verification.verificationPhrase)
    let progress = try await coordinator.submitDeviceConfirmation(confirmation)

    guard case .completed(let proposal) = progress else {
      throw PairingRunIncomplete()
    }
    return PairingRun(
      pairingSessionID: payload.pairingSessionID,
      deviceID: deviceID,
      devicePublicKey: deviceKey.publicKey.x963Representation,
      hostPhrase: acceptance.verificationPhrase,
      devicePhrase: verification.verificationPhrase,
      proposal: proposal
    )
  }
}

private struct PairingRunIncomplete: Error {}

/// The device's signer. On a phone this is a Secure Enclave key; here it is a
/// CryptoKit key behind the same seam.
private struct RawP256TranscriptSigner: PairingTranscriptSigner {
  let key: P256.Signing.PrivateKey

  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try key.signature(for: canonicalBytes).rawRepresentation
  }
}

/// A CryptoKit-backed identity backend, so identity behaviour is testable
/// without an entitled signed host.
private final class InMemoryIdentityBackend: SecureIdentityBackend {
  private final class Key: SecureIdentityKey {
    let key = P256.Signing.PrivateKey()
    func publicKeyX963() throws -> Data { key.publicKey.x963Representation }
    func signRaw(_ message: Data) throws -> Data {
      try key.signature(for: message).rawRepresentation
    }
    func validateRequiredAttributes() throws {}
    func assertNonExportable() throws {}
    func certificateSigner() throws -> Certificate.PrivateKey {
      Certificate.PrivateKey(key)
    }
  }

  private var claims: Set<BridgeIdentityRole> = []
  private var keys: [BridgeIdentityRole: [Key]] = [:]

  func insertClaim(for role: BridgeIdentityRole) throws -> BridgeClaimInsertion {
    claims.insert(role).inserted ? .inserted : .alreadyPresent
  }

  func claimCount(for role: BridgeIdentityRole) throws -> Int {
    claims.contains(role) ? 1 : 0
  }

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

/// The exact upgrade values the phone must send.
///
/// `PairingClient` on iOS cannot import `MacBridgeServer`, so it restates the
/// path, `Origin`, and subprotocol as its own literals. A divergence is not a
/// cosmetic mismatch: the listener refuses the upgrade before reading a single
/// pairing byte, and the phone sees a connection that simply closes — which is
/// indistinguishable from a network problem and is exactly how the first
/// real-device run failed.
///
/// These assertions are the second, independent statement of each constant, so
/// a change on either side fails here rather than on a phone.
final class PhoneUpgradeContractTests: XCTestCase {
  func testTheUpgradePathOriginAndSubprotocolAreWhatThePhoneSends() {
    XCTAssertEqual(ListenerUpgradePolicy.path, "/codex-micro/bridge/v1")
    XCTAssertEqual(ListenerUpgradePolicy.origin, "https://codex-micro-bridge.invalid")
    XCTAssertEqual(ListenerUpgradePolicy.subprotocol, "codex-micro.bridge.v1")
  }
}

/// Which side confirms last decides where the completion surfaces.
///
/// Pairing completes when the second of the two confirmations lands, and
/// either side can be second. The transport reports the device-last case;
/// `BridgePairingService` reports the Mac-last case. Both must reach the same
/// place, or a pairing "succeeds" on both screens while the Mac stores
/// nothing and the device is refused as unknown on its next connection.
///
/// Over a real network the phone is usually quicker than the person at the
/// Mac, so Mac-last is the ordinary case rather than the exotic one — which is
/// why this went unnoticed until a real device was on the other end.
final class PairingCompletionOrderingTests: XCTestCase {

  func testTheMacConfirmingLastStillRecordsTheGrant() async throws {
    let world = try await OrderedPairingWorld.make()

    // Device confirms first, so the Mac's confirmation is the one that
    // completes the pairing.
    _ = try await world.coordinator.submitDeviceConfirmation(world.deviceConfirmation)
    await world.service.confirmDisplayedPhrase()

    let stored = try await world.authority.authoritativeGrant(deviceID: world.deviceID)
    XCTAssertEqual(stored.capabilities, [.view])
    let state = await MainActor.run { world.model.state }
    XCTAssertEqual(state, .paired(deviceID: world.deviceID))
  }

  func testTheDeviceConfirmingLastStillRecordsTheGrant() async throws {
    let world = try await OrderedPairingWorld.make()

    // Mac confirms first; the device's confirmation completes the pairing and
    // the transport observer records it.
    await world.service.confirmDisplayedPhrase()
    let progress = try await world.coordinator.submitDeviceConfirmation(
      world.deviceConfirmation)
    guard case .completed(let proposal) = progress else {
      XCTFail("the device's confirmation did not complete the pairing")
      return
    }
    await world.observer.pairingCompleted(proposal)

    let stored = try await world.authority.authoritativeGrant(deviceID: world.deviceID)
    XCTAssertEqual(stored.capabilities, [.view])
  }
}

/// A claimed pairing session with the device's confirmation ready to submit,
/// so a test controls which side confirms last.
private struct OrderedPairingWorld {
  let coordinator: PairingCoordinator
  let service: BridgePairingService
  let observer: BridgePairingObserver
  let model: BridgePairingModel
  let authority: DeviceGrantAuthority
  let deviceID: UUID
  let deviceConfirmation: SecurePairingConfirmation

  static func make() async throws -> OrderedPairingWorld {
    let store = BridgeIdentityStore(backend: OrderedIdentityBackend(), resetPolicy: { false })
    let signer = try EnclaveHostStatementSigner(identity: try store.create(role: .host))
    let coordinator = try PairingCoordinator(
      hostID: UUID(uuidString: "F0F0F0F0-F0F0-F0F0-F0F0-F0F0F0F0F0F0")!,
      hostPublicKeyX963: signer.hostPublicKeyX963,
      signer: signer
    )
    let authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
    let model = await BridgePairingModel()
    let observer = BridgePairingObserver(
      model: model, recorder: PairingGrantRecorder(authority: authority))
    let service = BridgePairingService(
      coordinator: coordinator, model: model, observer: observer)

    let payload = try await coordinator.createSession(
      endpointOrigin: try PairingEndpointOrigin("wss://192.168.1.5:8443"),
      selection: try SecureProtocolSelection(major: 1, minor: 1, features: [.observeSync]),
      tlsSPKIFingerprint: Data(repeating: 0x31, count: 32)
    )
    let deviceKey = P256.Signing.PrivateKey()
    let deviceID = UUID(uuidString: "F1F1F1F1-F1F1-F1F1-F1F1-F1F1F1F1F1F1")!
    let device = PairingDeviceEndpoint(
      identity: try PairingDeviceIdentity(
        deviceID: deviceID,
        publicKeyX963: deviceKey.publicKey.x963Representation,
        signer: OrderedTranscriptSigner(key: deviceKey)
      ))
    let attempt = try device.beginPairing(with: payload)
    let acceptance = try await coordinator.claim(request: attempt.request)
    let verification = try attempt.verifyHostResponse(acceptance.response)

    // Put the phrase on screen exactly as the transport would, so the service
    // confirms the value the user is looking at.
    await observer.pairingClaimed(
      pairingSessionID: payload.pairingSessionID, phrase: acceptance.verificationPhrase)

    return OrderedPairingWorld(
      coordinator: coordinator,
      service: service,
      observer: observer,
      model: model,
      authority: authority,
      deviceID: deviceID,
      deviceConfirmation: try verification.confirmLocally(
        matching: verification.verificationPhrase)
    )
  }
}

private struct OrderedTranscriptSigner: PairingTranscriptSigner {
  let key: P256.Signing.PrivateKey
  func signPairingTranscript(_ canonicalBytes: Data) throws -> Data {
    try key.signature(for: canonicalBytes).rawRepresentation
  }
}

private final class OrderedIdentityBackend: SecureIdentityBackend {
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

/// Re-pairing a device the Mac already holds.
///
/// The authority refuses a duplicate on purpose: replacing the grant would
/// reset the grant revision and authorized-view epoch that the device's own
/// session counters are bound to, turning a redundant action into a
/// security-relevant one. But nothing went *wrong*, and reporting it as a bare
/// failure sent the reader looking for a broken write.
final class RepairedDeviceTests: XCTestCase {

  func testRePairingAKnownDeviceReportsAlreadyPairedRatherThanFailure() async throws {
    let authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
    let model = await BridgePairingModel()
    let observer = BridgePairingObserver(
      model: model, recorder: PairingGrantRecorder(authority: authority))
    let proposal = try await PairingRun.complete().proposal

    await observer.pairingCompleted(proposal)
    let first = await MainActor.run { model.state }
    XCTAssertEqual(first, .paired(deviceID: proposal.deviceID))

    await observer.pairingCompleted(proposal)
    let second = await MainActor.run { model.state }
    XCTAssertEqual(second, .alreadyPaired(deviceID: proposal.deviceID))
  }

  /// The existing grant must survive untouched. Its revision is what the
  /// device's session counters are bound to.
  func testRePairingLeavesTheExistingGrantUnchanged() async throws {
    let authority = DeviceGrantAuthority(
      storage: InMemoryGrantAuthorityStore(), clock: { 1_000_000 })
    let model = await BridgePairingModel()
    let observer = BridgePairingObserver(
      model: model, recorder: PairingGrantRecorder(authority: authority))
    let proposal = try await PairingRun.complete().proposal

    await observer.pairingCompleted(proposal)
    let before = try await authority.authoritativeGrant(deviceID: proposal.deviceID)
    await observer.pairingCompleted(proposal)
    let after = try await authority.authoritativeGrant(deviceID: proposal.deviceID)

    XCTAssertEqual(before.grantRevision, after.grantRevision)
    XCTAssertEqual(before.authorizedViewEpoch, after.authorizedViewEpoch)
    XCTAssertEqual(before.devicePublicKey, after.devicePublicKey)
  }
}

/// The phone's mirrored wire vocabularies.
///
/// The phone cannot import `MacBridgeServer`, so it restates the handshake and
/// application kinds as its own enums. A missing case is not a cosmetic
/// divergence — it is a message the phone can never send or recognise, and it
/// fails as a closed `protocolViolation` that looks like a transport problem.
/// One case (`sessionAuthConfirmation`) was in fact missing from the first
/// mirror and was caught only by the compiler happening to need it.
///
/// These assertions are the second, independent statement of each vocabulary.
final class PhoneWireVocabularyTests: XCTestCase {
  func testTheHandshakeKindsMatchWhatThePhoneMirrors() {
    XCTAssertEqual(
      Set(ListenerHandshakeKind.allCases.map(\.rawValue)),
      [
        "pairingRequest", "pairingResponse", "pairingConfirmation",
        "sessionAuthRequest", "sessionAuthResponse", "sessionAuthConfirmation",
        "closeNotice",
      ])
  }

  func testTheApplicationKindsMatchWhatThePhoneMirrors() {
    XCTAssertEqual(
      Set(ListenerApplicationKind.allCases.map(\.rawValue)),
      [
        "observationSubscribe", "observationAcknowledge", "commandRequest",
        "observationDelivery", "commandResult", "closeNotice",
      ])
  }

  /// The inbound allowlist is the security-relevant half: it decides what a
  /// device may send. The phone mirrors it to decide what it may *receive*,
  /// so the two must agree on every case.
  func testTheDeviceOriginatedAllowlistIsExactlyTheThreeDeviceMessages() {
    let deviceOriginated = ListenerApplicationKind.allCases
      .filter(\.isDeviceOriginated)
      .map(\.rawValue)

    XCTAssertEqual(
      Set(deviceOriginated),
      ["observationSubscribe", "observationAcknowledge", "commandRequest"])
  }
}
