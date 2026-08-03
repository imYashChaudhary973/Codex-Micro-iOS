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
    guard let url = URL(string: payload.endpointOrigin.normalized) else {
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
      await set(.comparing(words: verified.verificationPhrase.displayWords))
    } catch let failure as PairingClient.Failure {
      // A pin mismatch is the one failure worth naming distinctly on screen:
      // it means something on this network answered instead of the Mac.
      await set(.failed(reason: failure == .pinMismatch ? "pinMismatch" : "connectionFailed"))
    } catch {
      await set(.failed(reason: "hostRejected"))
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
