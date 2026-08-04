import CompanionCrypto
import CompanionProtocol
import Foundation
import SwiftUI

/// What the phone shows during pairing.
public enum PhonePairingState: Equatable, Sendable {
  case idle
  case scanning
  /// Connected and the host replied; these are the words to compare.
  case comparing(words: [String])
  /// The phone confirmed; the Mac user must confirm too.
  case awaitingMac
  case paired
  case failed(reason: String)
}

@MainActor
public final class PhonePairingModel: ObservableObject {
  @Published public private(set) var state: PhonePairingState = .idle

  public init() {}

  public func set(_ next: PhonePairingState) { state = next }
}

/// Drives the device half of pairing: scan, connect, verify, confirm.
///
/// The choreography lives in `CompanionCrypto`'s `PairingDeviceEndpoint`; this
/// carries its messages over the pinned socket and moves the screen along. It
/// makes no cryptographic decision of its own — in particular it never decides
/// that a phrase matches, because that is the user's job and the state machine
/// refuses to sign unless the phrase handed back equals the one it derived.
public actor PhonePairingFlow {
  private let model: PhonePairingModel
  private var client: PairingClient?
  private var verification: PairingDeviceVerification?

  public init(model: PhonePairingModel) {
    self.model = model
  }

  /// Runs everything up to the phrase comparison.
  ///
  /// Ordering matters and is fixed: the payload is decoded before anything is
  /// opened, the socket is pinned to the SPKI the payload carried before any
  /// byte is sent, and the host's reply is verified against the payload's host
  /// fingerprint before a phrase is shown. A phrase displayed after a failed
  /// verification would be a phrase the user might confirm.
  public func begin(scannedText: String) async {
    await set(.scanning)
    guard let payload = BridgePairingQRDecoding.payload(fromScanned: scannedText) else {
      await set(.failed(reason: "notOurCode"))
      return
    }

    let key: SecKey
    do {
      key = try DeviceIdentity.load() ?? DeviceIdentity.create()
    } catch {
      await set(.failed(reason: "identityUnavailable"))
      return
    }

    let endpoint: PairingDeviceEndpoint
    let attempt: PairingDeviceAttempt
    do {
      endpoint = PairingDeviceEndpoint(
        identity: try PairingDeviceIdentity(
          deviceID: DeviceInstallation.deviceID(),
          publicKeyX963: try DeviceIdentity.publicKeyX963(key),
          signer: EnclaveTranscriptSigner(key: key)
        ))
      attempt = try endpoint.beginPairing(with: payload)
    } catch {
      await set(.failed(reason: "payloadRejected"))
      return
    }

    let client = PairingClient(expectedSPKIFingerprint: payload.tlsSPKIFingerprint)
    self.client = client
    // The origin names host and port; the listener additionally requires an
    // exact path, so the URL is rebuilt rather than used verbatim.
    guard let origin = URL(string: payload.endpointOrigin.normalized),
      let host = origin.host,
      let url = PairingClient.url(host: host, port: origin.port ?? 443)
    else {
      await set(.failed(reason: "badEndpoint"))
      return
    }
    client.connect(to: url)

    do {
      let requestBody = try JSONEncoder().encode(attempt.request)
      let reply = try await client.exchange(
        ListenerHandshakeEnvelopeWire(kind: .pairingRequest, payload: requestBody))
      let envelope = try ListenerHandshakeEnvelopeWire.decode(reply)
      guard envelope.kind == .pairingResponse else {
        await set(.failed(reason: "refused"))
        return
      }
      let response = try JSONDecoder().decode(
        SecurePairingResponse.self, from: envelope.payload)
      let verified = try attempt.verifyHostResponse(response)
      verification = verified
      // Remember the host now, while the verified response is in hand. The
      // host's long-term public key is only available here — the QR carries a
      // fingerprint of it, and a fingerprint cannot verify a signature. Losing
      // this is why the phone could pair and then never reconnect.
      try? PairedHostStore.save(
        PairedHost(payload: payload, hostPublicKeyX963: response.hostPublicKey))
      await set(.comparing(words: verified.verificationPhrase.displayWords))
    } catch let failure as PairingClient.Failure {
      // A pin mismatch is the one failure worth naming distinctly on screen:
      // it means something on this network answered instead of the Mac.
      await set(.failed(reason: failure == .pinMismatch ? "pinMismatch" : "connectionFailed"))
    } catch let closed as PairingClosedReason {
      // The pairing state machine's own closed vocabulary. Collapsing these
      // into one word is what made the first real-device run undiagnosable.
      await set(.failed(reason: closed.rawValue))
    } catch {
      await set(.failed(reason: "hostRejected.\(type(of: error))"))
    }
  }

  /// The user says the words match. The state machine signs only if they
  /// actually do, so this cannot force a mismatched pairing through.
  public func confirmMatch() async {
    guard let verification, let client else { return }
    do {
      let confirmation = try verification.confirmLocally(
        matching: verification.verificationPhrase)
      let body = try JSONEncoder().encode(confirmation)
      try await client.send(
        ListenerHandshakeEnvelopeWire(kind: .pairingConfirmation, payload: body))
      // The host closes either way and the Mac user may not have confirmed
      // yet, so there is nothing to wait for on this socket.
      client.close()
      self.client = nil
      await set(.awaitingMac)
    } catch {
      await set(.failed(reason: "confirmationFailed"))
    }
  }

  public func cancel() async {
    client?.close()
    client = nil
    verification = nil
    await set(.idle)
  }

  private func set(_ next: PhonePairingState) async {
    await MainActor.run { model.set(next) }
  }
}

/// Drives pairing from a code supplied at launch instead of the camera.
///
/// **The camera is not the security boundary — the phrase is.** A scanned QR
/// and a code handed in at launch produce byte-identical payloads and travel
/// the identical transport, so this exercises everything the camera path does
/// except the optics. It exists because an acceptance run has to be
/// reproducible and readable, and nobody can diff a photograph of a phone.
///
/// It is an acceptance affordance, gated on a launch environment variable that
/// nothing persists and no shipped configuration sets. The camera remains the
/// only way a user pairs.
public enum PhoneAcceptanceRun {
  public static let codeKey = "CODEX_MICRO_PAIRING_CODE"

  public static var suppliedCode: String? {
    guard let code = ProcessInfo.processInfo.environment[codeKey], !code.isEmpty else {
      return nil
    }
    return code
  }

  static func report(_ step: String, _ detail: String = "") {
    let line = detail.isEmpty ? "phone: \(step)" : "phone: \(step) — \(detail)"
    FileHandle.standardError.write(Data((line + "\n").utf8))
    print(line)
  }

  /// Runs the device half and reports each step.
  ///
  /// The phrase is printed rather than compared here: with a real device the
  /// two phrases are derived on two machines from independently reconstructed
  /// transcripts, so comparing them means reading both runs' output — which is
  /// exactly what a user does with their eyes.
  public static func run(code: String, model: PhonePairingModel) async {
    report("start")
    let flow = PhonePairingFlow(model: model)
    await flow.begin(scannedText: code)

    let state = await MainActor.run { model.state }
    switch state {
    case .comparing(let words):
      report("phrase.device", words.joined(separator: " "))
      await flow.confirmMatch()
      let next = await MainActor.run { model.state }
      if case .failed(let reason) = next {
        report("confirm.failed", reason)
      } else {
        report("confirm.sent", "awaiting the Mac")
      }
    case .failed(let reason):
      report("failed", reason)
    default:
      report("unexpectedState", "\(state)")
    }
  }
}

/// Decodes the QR text. Mirrors the Mac's encoder.
public enum BridgePairingQRDecoding {
  public static func payload(fromScanned text: String) -> PairingQRPayload? {
    guard let data = Data(base64Encoded: text) else { return nil }
    return try? PairingQRPayload(canonicalEncoding: data)
  }
}

/// The device identifier this installation presents.
///
/// It is minted once and stored, so a relaunch keeps the same identity while a
/// *reinstall* produces a new one — which is the behaviour acceptance case 1
/// distinguishes, since the Enclave key survives neither and the Mac's grant
/// survives both.
public enum DeviceInstallation {
  private static let key = "com.codexmicro.acceptance.device-id"

  public static func deviceID() -> UUID {
    if let stored = UserDefaults.standard.string(forKey: key),
      let id = UUID(uuidString: stored)
    {
      return id
    }
    let id = UUID()
    UserDefaults.standard.set(id.uuidString, forKey: key)
    return id
  }
}
