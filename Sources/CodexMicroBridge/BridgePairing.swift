import CompanionCrypto
import CompanionProtocol
import CoreImage
import Foundation
import MacBridgeCore
import MacBridgeServer
import SwiftUI

/// What the Mac shows during pairing.
///
/// The states are ordered by what the user must do next, not by protocol
/// phase, because the screen exists to answer exactly one question at a time:
/// scan this, or compare this, or you are done.
public enum BridgePairingState: Equatable, Sendable {
  /// No pairing session. The Mac is not advertising a secret.
  case idle
  /// A session exists and its QR is on screen. The bootstrap secret is live.
  case awaitingScan(qrText: String, expiresAtEpochSeconds: UInt64)
  /// The device is already paired, and the existing grant was kept.
  ///
  /// Distinct from ``failed(reason:)`` because nothing went wrong. A device
  /// that re-pairs without first being removed keeps the grant it has, and
  /// silently replacing it would reset the grant revision and authorized-view
  /// epoch that the device's own session counters are bound to — turning a
  /// redundant action into a security-relevant one.
  case alreadyPaired(deviceID: UUID)
  /// The device claimed. The user compares this phrase with the phone.
  ///
  /// The phrase itself is carried, not its rendered words. The confirm step
  /// re-uses this exact value, so what the coordinator is told the user
  /// confirmed is necessarily the value the words were rendered from — there
  /// is no parse step between display and confirmation that could disagree.
  case awaitingPhrase(pairingSessionID: UUID, phrase: SecureShortAuthenticationString)
  /// The Mac user confirmed; the device has not yet.
  case awaitingDevice(pairingSessionID: UUID)
  /// Pairing completed and the grant is stored.
  case paired(deviceID: UUID)
  /// Pairing failed. The reason is closed vocabulary.
  case failed(reason: String)
}

/// The Mac's pairing screen state, and the only place it is mutated.
///
/// `@MainActor` because it drives a view; the observer below hops here rather
/// than letting the transport touch view state from a connection's task.
@MainActor
public final class BridgePairingModel: ObservableObject {
  @Published public private(set) var state: BridgePairingState = .idle

  public init() {}

  public func set(_ next: BridgePairingState) { state = next }

  /// The phrase currently awaiting comparison, if any. The confirm button
  /// reads this rather than being handed a phrase, so the thing confirmed is
  /// necessarily the thing displayed.
  public var pendingPairingSessionID: UUID? {
    switch state {
    case .awaitingPhrase(let id, _): return id
    default: return nil
    }
  }

  /// The six words on screen, or empty when no phrase is pending.
  public var pendingWords: [String] {
    switch state {
    case .awaitingPhrase(_, let phrase): return phrase.displayWords
    default: return []
    }
  }
}

/// Receives the two pairing facts the transport learns and does the two
/// things the transport cannot: show the phrase, and store the grant.
///
/// **The grant is recorded before the user is told they are paired.** If
/// `addGrant` throws — a duplicate device, an unavailable authority — the
/// screen says failed, because a screen that says "paired" while the Mac
/// holds no grant would send the user to a phone that is about to be refused
/// as unknown.
public struct BridgePairingObserver: ListenerPairingObserving {
  private let model: BridgePairingModel
  private let recorder: PairingGrantRecorder

  public init(model: BridgePairingModel, recorder: PairingGrantRecorder) {
    self.model = model
    self.recorder = recorder
  }

  public func pairingClaimed(
    pairingSessionID: UUID,
    phrase: SecureShortAuthenticationString
  ) async {
    await MainActor.run {
      model.set(.awaitingPhrase(pairingSessionID: pairingSessionID, phrase: phrase))
    }
  }

  /// Reports a refused session on the Mac's own output.
  ///
  /// Goes to standard error rather than to the pairing model, because it is
  /// not a pairing state: the device is already paired and is being turned
  /// away for some other reason. Putting it in the model would overwrite a
  /// finished pairing with a failure that is about something else.
  public func sessionAuthenticationFailed(stage: String, reason: String) async {
    FileHandle.standardError.write(
      Data("codex-micro: session.refused.\(stage) — \(reason)\n".utf8))
  }

  public func sessionAuthenticated(deviceID: UUID) async {
    FileHandle.standardError.write(Data("codex-micro: session.authenticated\n".utf8))
  }

  public func pairingCompleted(_ proposal: PairedDeviceProposal) async {
    let deviceID = proposal.deviceID
    do {
      _ = try await recorder.record(proposal)
      await MainActor.run { model.set(.paired(deviceID: deviceID)) }
    } catch DeviceGrantAuthorityError.duplicateDevice {
      // Re-pairing a device the Mac already holds. The authority refuses on
      // purpose and the existing grant stands; reporting this as a failure
      // sent the reader looking for a broken write when the honest answer is
      // "this device is already paired".
      await MainActor.run { model.set(.alreadyPaired(deviceID: deviceID)) }
    } catch DeviceGrantAuthorityError.deviceRevoked {
      await MainActor.run { model.set(.failed(reason: "deviceRevoked")) }
    } catch DeviceGrantAuthorityError.deviceExpired {
      await MainActor.run { model.set(.failed(reason: "grantExpired")) }
    } catch let failure as DeviceGrantAuthorityError {
      await MainActor.run { model.set(.failed(reason: "grantNotStored.\(failure)")) }
    } catch {
      await MainActor.run { model.set(.failed(reason: "grantNotStored")) }
    }
  }
}

/// Renders the pairing payload as a scannable QR.
///
/// **The payload travels as base64 text, not raw bytes.** A QR can carry
/// binary, but `AVCaptureMetadataOutput` hands a scanned code back as a
/// `String`, and pushing arbitrary bytes through that round-trip corrupts
/// them. Base64 costs about a third more modules and removes the failure
/// mode entirely.
public enum BridgePairingQR {
  /// The text encoded into the QR, and what the phone decodes back.
  public static func text(for payload: PairingQRPayload) -> String {
    payload.canonicalEncoding().base64EncodedString()
  }

  /// Decodes a scanned string back to a payload, or `nil` when the code was
  /// not one of ours. Strict on both steps: a wrong base64 or a canonical
  /// encoding that fails validation are both simply "not our code".
  public static func payload(fromScanned text: String) -> PairingQRPayload? {
    guard let data = Data(base64Encoded: text) else { return nil }
    return try? PairingQRPayload(canonicalEncoding: data)
  }

  /// A QR image at a size worth pointing a phone at.
  public static func image(for text: String, scale: CGFloat = 10) -> CGImage? {
    guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
    filter.setValue(Data(text.utf8), forKey: "inputMessage")
    // Medium error correction. The code is on a screen a foot away, not on a
    // scuffed label, so spending modules on redundancy would only shrink the
    // features the camera has to resolve.
    filter.setValue("M", forKey: "inputCorrectionLevel")
    guard let output = filter.outputImage else { return nil }
    let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
    return CIContext().createCGImage(scaled, from: scaled.extent)
  }
}

/// Owns one pairing session's lifecycle on the Mac.
///
/// The coordinator is transport-independent and stores nothing; this is the
/// piece that decides *when* a session exists, publishes its QR, and applies
/// the Mac user's confirmation. It deliberately holds no authority of its
/// own — the grant is written by ``BridgePairingObserver`` on the completion
/// path, so there is exactly one place a pairing turns into a grant.
public actor BridgePairingService {
  private let coordinator: PairingCoordinator
  private let model: BridgePairingModel
  /// Where a completion discovered on *this* side goes.
  ///
  /// Pairing completes when the second of the two confirmations lands, and
  /// either side can be second. The transport reports the case where the
  /// device confirms last; this reports the case where the Mac user does.
  /// Both must reach the same place or a pairing succeeds while the Mac
  /// stores nothing — see ``confirmDisplayedPhrase()``.
  private let observer: any ListenerPairingObserving
  private var activeSessionID: UUID?

  public init(
    coordinator: PairingCoordinator,
    model: BridgePairingModel,
    observer: any ListenerPairingObserving = DiscardingListenerPairingObserver()
  ) {
    self.coordinator = coordinator
    self.model = model
    self.observer = observer
  }

  /// Opens a pairing session against a bound endpoint and publishes its QR.
  ///
  /// The endpoint and the served SPKI both come from the listener that is
  /// actually running, so the QR can never advertise a fingerprint the Mac is
  /// not serving or an address it is not bound to.
  @discardableResult
  public func beginPairing(
    endpoint: ListenerEndpoint,
    selection: SecureProtocolSelection
  ) async throws -> PairingQRPayload {
    let origin = try PairingEndpointOrigin("wss://\(endpoint.host):\(endpoint.port)")
    let payload = try await coordinator.createSession(
      endpointOrigin: origin,
      selection: selection,
      tlsSPKIFingerprint: endpoint.spkiFingerprint
    )
    activeSessionID = payload.pairingSessionID
    let text = BridgePairingQR.text(for: payload)
    let expiry = payload.expiresAtEpochSeconds
    await MainActor.run {
      model.set(.awaitingScan(qrText: text, expiresAtEpochSeconds: expiry))
    }
    return payload
  }

  /// Applies the Mac user's confirmation that the displayed phrase matches
  /// the phone's.
  ///
  /// The phrase comes from the displayed state rather than from the caller,
  /// so what gets confirmed is necessarily what was shown. A caller cannot
  /// confirm a phrase the user never saw.
  /// **This call can complete the pairing.** `confirmVerificationPhrase`
  /// returns `.completed` when the device already confirmed, which is the
  /// ordinary case whenever the phone is quicker than the person at the Mac —
  /// and over a real network it usually is. Discarding that result left the
  /// screen on "waiting for the device" forever and stored no grant, while
  /// both sides believed they had confirmed.
  public func confirmDisplayedPhrase() async {
    guard let (sessionID, phrase) = await currentPhrase() else { return }
    let progress: PairingProgress
    do {
      progress = try await coordinator.confirmVerificationPhrase(
        pairingSessionID: sessionID, phrase: phrase)
    } catch {
      await MainActor.run { model.set(.failed(reason: "phraseRejected")) }
      return
    }
    switch progress {
    case .completed(let proposal):
      await observer.pairingCompleted(proposal)
    case .awaitingConfirmation:
      await MainActor.run { model.set(.awaitingDevice(pairingSessionID: sessionID)) }
    }
  }

  /// Cancels the active session, destroying its secret.
  public func cancel() async {
    if let activeSessionID {
      await coordinator.cancel(pairingSessionID: activeSessionID)
    }
    activeSessionID = nil
    await MainActor.run { model.set(.idle) }
  }

  private func currentPhrase() async -> (UUID, SecureShortAuthenticationString)? {
    await MainActor.run {
      if case .awaitingPhrase(let id, let phrase) = model.state { return (id, phrase) }
      return nil
    }
  }
}
