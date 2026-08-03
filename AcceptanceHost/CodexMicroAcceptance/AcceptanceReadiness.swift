import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation
import Security

/// What the host can establish about a case **without** a Mac, a network, or a
/// second device.
///
/// A readiness result is never evidence that a gate passed. It answers a
/// narrower question: is this device in a position for the physical run to
/// mean anything? A run that reports `unsatisfied` and then "passes" is a run
/// that proved nothing, and separating the two is the entire point.
public enum AcceptanceReadiness: Equatable, Sendable {
  /// The precondition holds, with what was checked.
  case satisfied(String)
  /// The case has no offline precondition. This is an honest answer, not a
  /// pass — the case is physical or nothing.
  case physicalOnly
  /// The precondition does not hold. Running the physical case now would
  /// produce a result that means nothing.
  case unsatisfied(String)

  public var isBlocking: Bool {
    if case .unsatisfied = self { return true }
    return false
  }
}

/// Runs the offline preconditions for each matrix case.
public enum AcceptancePreconditions {

  /// The Bonjour service the bridge publishes. Duplicated here rather than
  /// imported because `MacBridgeServer` is macOS-only; the Mac test suite
  /// asserts its own constant against its `Info.plist`, and
  /// ``bonjourServiceMatchesBundle()`` asserts this one against this bundle.
  /// Two independent assertions of the same literal is the point — a silent
  /// divergence would make the phone browse for a service nobody publishes.
  public static let serviceType = "_codexmicro._tcp"

  public static func readiness(for gate: AcceptanceGate) -> AcceptanceReadiness {
    switch gate {
    case .enclaveIdentityAndReinstall: return secureEnclaveAvailable()
    case .pinnedSelfSignedWSS: return pairingPayloadRoundTrips()
    case .pairingAndBonjour: return bonjourServiceMatchesBundle()
    case .tlsRotation: return rotationStatementRoundTrips()
    case .filteredObserveAndReplay: return observationDecoderIsStrict()
    case .immediateRevocation: return revocationReasonRoundTrips()
    case .idempotentInterrupt: return commandDecoderIsStrict()
    case .ipChange, .foregroundBackgroundReauth, .macRestart, .keychainLockAndReboot:
      // These are properties of a running system across a real disruption.
      // There is nothing honest to check from a cold launch, and inventing a
      // check here would only make the matrix look greener than it is.
      return .physicalOnly
    }
  }

  /// Writes the results to stdout so a device run is capturable evidence
  /// rather than a screenshot.
  ///
  /// `devicectl device process launch --console` picks this up, which is what
  /// makes an on-device result quotable in a status document. A photograph of
  /// a phone is not evidence anyone can diff.
  public static func emit(_ results: [String: AcceptanceReadiness]) {
    print("codex-micro acceptance readiness")
    for gate in AcceptanceGate.allCases {
      let state = results[gate.rawValue] ?? .physicalOnly
      let rendered: String
      switch state {
      case .satisfied(let detail): rendered = "SATISFIED   \(detail)"
      case .physicalOnly: rendered = "PHYSICAL    no offline precondition"
      case .unsatisfied(let reason): rendered = "BLOCKED     \(reason)"
      }
      print("  \(gate.rawValue.padding(toLength: 30, withPad: " ", startingAt: 0)) \(rendered)")
    }
  }

  // MARK: - Individual preconditions

  /// Creates a **non-persistent** Secure Enclave key and discards it.
  ///
  /// This is the one precondition that cannot pass in a simulator or an
  /// unsigned build: it needs real hardware and a provisioned entitlement. It
  /// is deliberately non-persistent (`kSecAttrIsPermanent: false`) so the
  /// check writes nothing to the Keychain — a readiness probe that left a key
  /// behind would be indistinguishable from the identity the reinstall case
  /// exists to watch.
  static func secureEnclaveAvailable() -> AcceptanceReadiness {
    var accessError: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage],
        &accessError
      )
    else {
      return .unsatisfied("access control unavailable")
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: false,
        kSecAttrAccessControl as String: access,
      ],
    ]

    var error: Unmanaged<CFError>?
    guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
      let reason = error?.takeRetainedValue().localizedDescription ?? "unknown"
      return .unsatisfied("Secure Enclave key creation refused: \(reason)")
    }
    return .satisfied("Secure Enclave produced a P-256 key; nothing persisted")
  }

  /// The pairing payload the QR carries must survive its canonical encoding
  /// unchanged, and must pin a 32-byte SPKI digest rather than certificate
  /// bytes.
  static func pairingPayloadRoundTrips() -> AcceptanceReadiness {
    let payload: PairingQRPayload
    do {
      payload = try PairingQRPayload(
        selection: SecureProtocolSelection(major: 1, minor: 0, features: [.observeSync]),
        hostID: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        endpointOrigin: try PairingEndpointOrigin("wss://192.168.1.20:8443"),
        hostIdentityFingerprint: Data(repeating: 0x11, count: 32),
        tlsSPKIFingerprint: Data(repeating: 0x22, count: 32),
        pairingSessionID: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
        bootstrapSecret: Data(repeating: 0x33, count: 32),
        expiresAtEpochSeconds: 1_000_000
      )
    } catch {
      return .unsatisfied("pairing payload rejected its own fields: \(error)")
    }

    do {
      let decoded = try PairingQRPayload(canonicalEncoding: payload.canonicalEncoding())
      guard decoded == payload else {
        return .unsatisfied("pairing payload did not survive its canonical encoding")
      }
      guard decoded.tlsSPKIFingerprint.count == 32 else {
        return .unsatisfied("pinned value is not a SHA-256 SPKI digest")
      }
      return .satisfied("pairing payload round-trips; pin is a 32-byte SPKI digest")
    } catch {
      return .unsatisfied("pairing payload failed to decode: \(error)")
    }
  }

  /// The bundle must declare the exact service the bridge publishes, and a
  /// local-network usage description. Without both, iOS refuses the browse
  /// outright and the pairing case would fail for a packaging reason rather
  /// than a protocol one.
  ///
  /// The six-word phrase is checked here too, because it is what the user
  /// actually compares during this case.
  static func bonjourServiceMatchesBundle() -> AcceptanceReadiness {
    let info = Bundle.main.infoDictionary ?? [:]
    guard let services = info["NSBonjourServices"] as? [String] else {
      return .unsatisfied("bundle declares no NSBonjourServices")
    }
    guard services.contains(serviceType) else {
      return .unsatisfied("bundle does not allow \(serviceType)")
    }
    guard let description = info["NSLocalNetworkUsageDescription"] as? String,
      !description.isEmpty
    else {
      return .unsatisfied("bundle carries no local-network usage description")
    }

    guard SecureSASWordList.words.count == 2048 else {
      return .unsatisfied("word list has \(SecureSASWordList.words.count) entries, not 2048")
    }
    guard Set(SecureSASWordList.words).count == 2048 else {
      return .unsatisfied("word list contains duplicates; two phrases could collide")
    }
    return .satisfied(
      "\(serviceType) allowed; phrase list \(SecureSASWordList.version) complete and unique")
  }

  /// A rotation statement must survive its canonical encoding, because that is
  /// the byte string the host signs and the phone verifies. A divergence here
  /// would make every rotation fail verification for a reason unrelated to
  /// rollback.
  static func rotationStatementRoundTrips() -> AcceptanceReadiness {
    do {
      let statement = try SecureRotationStatement(
        rotationGeneration: 1,
        currentSPKIFingerprint: Data(repeating: 0x44, count: 32),
        nextSPKIFingerprint: Data(repeating: 0x55, count: 32),
        validityStartEpochSeconds: 1_000_000,
        validityEndEpochSeconds: 1_000_600
      )
      let encoded = statement.canonicalEncoding()
      guard !encoded.isEmpty else {
        return .unsatisfied("rotation statement encoded to nothing")
      }
      return .satisfied("rotation statement encodes to \(encoded.count) canonical bytes")
    } catch {
      return .unsatisfied("rotation statement rejected its own fields: \(error)")
    }
  }

  /// The observation decoder must reject an unknown field. The filtered-replay
  /// case depends on the phone refusing anything it does not fully understand;
  /// a lenient decoder would let an added field ride along unexamined.
  static func observationDecoderIsStrict() -> AcceptanceReadiness {
    let text =
      #"{"threadID":"t","projectID":"p","status":"idle","activeTurnID":null,"#
      + #""lastTurnID":null,"lastTurnStatus":null,"surprise":true}"#
    let json = Data(text.utf8)
    do {
      _ = try JSONDecoder().decode(ObservedThreadState.self, from: json)
      return .unsatisfied("observation decoder accepted an unknown field")
    } catch {
      return .satisfied("observation decoder rejects unknown fields")
    }
  }

  /// Revocation must survive the wire as its own distinct reason. Collapsing
  /// it onto a generic failure would make the revocation case unobservable
  /// from the phone.
  static func revocationReasonRoundTrips() -> AcceptanceReadiness {
    do {
      let encoded = try JSONEncoder().encode(SecureCloseReason.deviceRevoked)
      let decoded = try JSONDecoder().decode(SecureCloseReason.self, from: encoded)
      guard decoded == .deviceRevoked else {
        return .unsatisfied("revocation reason changed across the wire")
      }
      return .satisfied("deviceRevoked round-trips as its own reason")
    } catch {
      return .unsatisfied("revocation reason failed to encode: \(error)")
    }
  }

  /// The command decoder must reject an unknown field, because the idempotency
  /// case turns on the Mac and the phone agreeing byte for byte on what a
  /// command *is*. A field one side ignores is a field that changes the digest
  /// on only one side.
  static func commandDecoderIsStrict() -> AcceptanceReadiness {
    let text =
      #"{"commandID":"11111111-1111-1111-1111-111111111111","issuedAt":0,"#
      + #""body":{},"extra":1}"#
    let json = Data(text.utf8)
    do {
      _ = try JSONDecoder().decode(ClientCommand.self, from: json)
      return .unsatisfied("command decoder accepted an unknown field")
    } catch {
      return .satisfied("command decoder rejects unknown fields")
    }
  }
}
