import CompanionCrypto
import CompanionProtocol
import CryptoKit
import Foundation

extension Data {
  init(hexFixture: String) {
    precondition(hexFixture.count.isMultiple(of: 2), "hex fixture requires an even digit count")
    var bytes = [UInt8]()
    bytes.reserveCapacity(hexFixture.count / 2)
    var iterator = hexFixture.makeIterator()
    while let high = iterator.next(), let low = iterator.next() {
      guard let value = UInt8(String([high, low]), radix: 16) else {
        preconditionFailure("hex fixture contains a non-hex digit")
      }
      bytes.append(value)
    }
    self.init(bytes)
  }

  var hexFixture: String {
    map { String(format: "%02x", $0) }.joined()
  }
}

/// Deterministic keys, identifiers, and canonical inputs shared by every
/// CompanionCrypto test. All values are fixed so golden vectors are
/// byte-exact and client/server roles can be exercised independently.
enum CryptoFixtures {
  static let pairingSessionID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
  static let hostID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
  static let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  static let sessionID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
  static let connectionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
  static let otherConnectionID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!
  static let otherUUID = UUID(uuidString: "99999999-9999-9999-9999-999999999999")!

  static let endpointOrigin = "wss://192.168.4.20:8443"

  static func scalar(startingAt first: UInt8) -> Data {
    Data((0..<32).map { first + UInt8($0) })
  }

  static let hostSigningKey = try! P256.Signing.PrivateKey(
    rawRepresentation: scalar(startingAt: 0x01))
  static let deviceSigningKey = try! P256.Signing.PrivateKey(
    rawRepresentation: scalar(startingAt: 0x21))
  static let clientEphemeralKey = try! P256.KeyAgreement.PrivateKey(
    rawRepresentation: scalar(startingAt: 0x41))
  static let serverEphemeralKey = try! P256.KeyAgreement.PrivateKey(
    rawRepresentation: scalar(startingAt: 0x61))
  static let tlsCurrentKey = try! P256.Signing.PrivateKey(
    rawRepresentation: scalar(startingAt: 0x81))
  static let tlsNextKey = try! P256.Signing.PrivateKey(
    rawRepresentation: scalar(startingAt: 0xA1))

  static var hostPublicKeyX963: Data { hostSigningKey.publicKey.x963Representation }
  static var devicePublicKeyX963: Data { deviceSigningKey.publicKey.x963Representation }
  static var clientEphemeralPublicKeyX963: Data {
    clientEphemeralKey.publicKey.x963Representation
  }
  static var serverEphemeralPublicKeyX963: Data {
    serverEphemeralKey.publicKey.x963Representation
  }
  static var tlsCurrentSPKIFingerprint: Data {
    SPKIFingerprint.fingerprint(of: tlsCurrentKey.publicKey)
  }
  static var tlsNextSPKIFingerprint: Data {
    SPKIFingerprint.fingerprint(of: tlsNextKey.publicKey)
  }

  static let bootstrapSecret = Data(repeating: 0xB5, count: 32)
  static let pairingDeviceNonce = Data(repeating: 0xD1, count: 32)
  static let pairingHostNonce = Data(repeating: 0xE2, count: 32)
  static let sessionDeviceNonce = Data(repeating: 0xC4, count: 32)
  static let sessionHostNonce = Data(repeating: 0xF7, count: 32)

  static let keyScheduleIKM = SymmetricKey(data: Data(repeating: 0x4B, count: 32))

  static func selection() throws -> SecureProtocolSelection {
    try SecureProtocolSelection(major: 1, minor: 1, features: Set(SecureProtocolFeature.allCases))
  }

  static func alternateMinorSelection() throws -> SecureProtocolSelection {
    try SecureProtocolSelection(major: 1, minor: 2, features: Set(SecureProtocolFeature.allCases))
  }

  static func alternateMajorSelection() throws -> SecureProtocolSelection {
    try SecureProtocolSelection(major: 2, minor: 1, features: Set(SecureProtocolFeature.allCases))
  }

  static func reducedFeatureSelection() throws -> SecureProtocolSelection {
    try SecureProtocolSelection(major: 1, minor: 1, features: [.observeSync])
  }

  static func mutated(_ data: Data, at index: Int) -> Data {
    var copy = data
    copy[index] ^= 0xFF
    return copy
  }

  static func pairingTranscript(
    pairingSessionID: UUID = CryptoFixtures.pairingSessionID,
    endpointOrigin: String = CryptoFixtures.endpointOrigin,
    selection: SecureProtocolSelection? = nil,
    bootstrapSecret: Data = CryptoFixtures.bootstrapSecret,
    deviceNonce: Data = CryptoFixtures.pairingDeviceNonce,
    devicePublicKey: Data? = nil,
    hostID: UUID = CryptoFixtures.hostID,
    hostNonce: Data = CryptoFixtures.pairingHostNonce,
    hostPublicKey: Data? = nil,
    hostTLSSPKIFingerprint: Data? = nil
  ) throws -> PairingTranscript {
    try PairingTranscript(
      pairingSessionID: pairingSessionID,
      mode: .directLAN,
      endpointOrigin: endpointOrigin,
      selection: selection ?? CryptoFixtures.selection(),
      bootstrapSecret: bootstrapSecret,
      deviceNonce: deviceNonce,
      devicePublicKey: devicePublicKey ?? devicePublicKeyX963,
      hostID: hostID,
      hostNonce: hostNonce,
      hostPublicKey: hostPublicKey ?? hostPublicKeyX963,
      hostTLSSPKIFingerprint: hostTLSSPKIFingerprint ?? tlsCurrentSPKIFingerprint
    )
  }

  /// Every pairing-transcript field mutated independently. `mode` has a
  /// single-case closed vocabulary in Phase 2 and cannot be mutated.
  static func mutatedPairingTranscripts() throws -> [(field: String, PairingTranscript)] {
    [
      ("pairingSessionID", try pairingTranscript(pairingSessionID: otherUUID)),
      ("endpointOrigin", try pairingTranscript(endpointOrigin: "wss://192.168.4.21:8443")),
      ("selection.major", try pairingTranscript(selection: alternateMajorSelection())),
      ("selection.minor", try pairingTranscript(selection: alternateMinorSelection())),
      ("selection.features", try pairingTranscript(selection: reducedFeatureSelection())),
      ("bootstrapSecret", try pairingTranscript(bootstrapSecret: mutated(bootstrapSecret, at: 0))),
      ("deviceNonce", try pairingTranscript(deviceNonce: mutated(pairingDeviceNonce, at: 31))),
      (
        "devicePublicKey",
        try pairingTranscript(devicePublicKey: mutated(devicePublicKeyX963, at: 30))
      ),
      ("hostID", try pairingTranscript(hostID: otherUUID)),
      ("hostNonce", try pairingTranscript(hostNonce: mutated(pairingHostNonce, at: 15))),
      ("hostPublicKey", try pairingTranscript(hostPublicKey: mutated(hostPublicKeyX963, at: 40))),
      (
        "hostTLSSPKIFingerprint",
        try pairingTranscript(hostTLSSPKIFingerprint: mutated(tlsCurrentSPKIFingerprint, at: 7))
      ),
    ]
  }

  static func sessionTranscript(
    sessionID: UUID = CryptoFixtures.sessionID,
    deviceID: UUID = CryptoFixtures.deviceID,
    selection: SecureProtocolSelection? = nil,
    deviceEphemeralPublicKey: Data? = nil,
    deviceNonce: Data = CryptoFixtures.sessionDeviceNonce,
    hostEphemeralPublicKey: Data? = nil,
    hostNonce: Data = CryptoFixtures.sessionHostNonce,
    grantRevision: UInt64 = 7,
    authorizedViewEpoch: UInt64 = 3,
    hostGeneration: UInt64 = 1
  ) throws -> SessionTranscript {
    try SessionTranscript(
      sessionID: sessionID,
      deviceID: deviceID,
      selection: selection ?? CryptoFixtures.selection(),
      deviceEphemeralPublicKey: deviceEphemeralPublicKey ?? clientEphemeralPublicKeyX963,
      deviceNonce: deviceNonce,
      hostEphemeralPublicKey: hostEphemeralPublicKey ?? serverEphemeralPublicKeyX963,
      hostNonce: hostNonce,
      grantRevision: grantRevision,
      authorizedViewEpoch: authorizedViewEpoch,
      hostGeneration: hostGeneration
    )
  }

  /// Every session-transcript field mutated independently.
  static func mutatedSessionTranscripts() throws -> [(field: String, SessionTranscript)] {
    [
      ("sessionID", try sessionTranscript(sessionID: otherUUID)),
      ("deviceID", try sessionTranscript(deviceID: otherUUID)),
      ("selection.major", try sessionTranscript(selection: alternateMajorSelection())),
      ("selection.minor", try sessionTranscript(selection: alternateMinorSelection())),
      ("selection.features", try sessionTranscript(selection: reducedFeatureSelection())),
      (
        "deviceEphemeralPublicKey",
        try sessionTranscript(
          deviceEphemeralPublicKey: mutated(clientEphemeralPublicKeyX963, at: 20))
      ),
      ("deviceNonce", try sessionTranscript(deviceNonce: mutated(sessionDeviceNonce, at: 0))),
      (
        "hostEphemeralPublicKey",
        try sessionTranscript(hostEphemeralPublicKey: mutated(serverEphemeralPublicKeyX963, at: 50))
      ),
      ("hostNonce", try sessionTranscript(hostNonce: mutated(sessionHostNonce, at: 16))),
      ("grantRevision", try sessionTranscript(grantRevision: 8)),
      ("authorizedViewEpoch", try sessionTranscript(authorizedViewEpoch: 4)),
      ("hostGeneration", try sessionTranscript(hostGeneration: 2)),
    ]
  }

  static func rotationStatement(
    rotationGeneration: UInt64 = 3,
    currentSPKIFingerprint: Data? = nil,
    nextSPKIFingerprint: Data? = nil,
    validityStartEpochSeconds: UInt64 = 1_754_000_000,
    validityEndEpochSeconds: UInt64 = 1_754_086_400
  ) throws -> SecureRotationStatement {
    try SecureRotationStatement(
      rotationGeneration: rotationGeneration,
      currentSPKIFingerprint: currentSPKIFingerprint ?? tlsCurrentSPKIFingerprint,
      nextSPKIFingerprint: nextSPKIFingerprint ?? tlsNextSPKIFingerprint,
      validityStartEpochSeconds: validityStartEpochSeconds,
      validityEndEpochSeconds: validityEndEpochSeconds
    )
  }

  /// Every rotation-statement field mutated independently.
  static func mutatedRotationStatements() throws -> [(field: String, SecureRotationStatement)] {
    [
      ("rotationGeneration", try rotationStatement(rotationGeneration: 4)),
      (
        "currentSPKIFingerprint",
        try rotationStatement(currentSPKIFingerprint: mutated(tlsCurrentSPKIFingerprint, at: 0))
      ),
      (
        "nextSPKIFingerprint",
        try rotationStatement(nextSPKIFingerprint: mutated(tlsNextSPKIFingerprint, at: 31))
      ),
      (
        "validityStartEpochSeconds",
        try rotationStatement(validityStartEpochSeconds: 1_754_000_001)
      ),
      ("validityEndEpochSeconds", try rotationStatement(validityEndEpochSeconds: 1_754_086_401)),
    ]
  }
}
