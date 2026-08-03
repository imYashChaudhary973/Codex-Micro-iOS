import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

final class KeyScheduleTests: XCTestCase {
  private func keyBytes(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes { Data($0) }
  }

  func testDirectionalKeysMatchGoldenVectors() throws {
    let keys = try CryptoFixtures.frameKeys()
    XCTAssertEqual(keyBytes(keys.clientToServer).hexFixture, GoldenVectors.clientToServerKeyHex)
    XCTAssertEqual(keyBytes(keys.serverToClient).hexFixture, GoldenVectors.serverToClientKeyHex)
  }

  func testDerivedKeysAreExactly32Bytes() throws {
    let keys = try CryptoFixtures.frameKeys()
    XCTAssertEqual(keys.clientToServer.bitCount, 256)
    XCTAssertEqual(keys.serverToClient.bitCount, 256)
    XCTAssertEqual(SecureSessionKeySchedule.frameKeyByteCount, 32)
  }

  func testDirectionalKeysAreDistinct() throws {
    let keys = try CryptoFixtures.frameKeys()
    XCTAssertNotEqual(keys.clientToServer, keys.serverToClient)
  }

  func testClientAndServerDeriveIdenticalKeysFromECDH() throws {
    let transcriptHash = try CryptoFixtures.sessionTranscript().canonicalHash()
    let clientSecret = try SecureKeyAgreement.sharedSecret(
      privateKey: CryptoFixtures.clientEphemeralKey,
      peerPublicKeyX963: CryptoFixtures.serverEphemeralPublicKeyX963)
    let serverSecret = try SecureKeyAgreement.sharedSecret(
      privateKey: CryptoFixtures.serverEphemeralKey,
      peerPublicKeyX963: CryptoFixtures.clientEphemeralPublicKeyX963)

    let clientKeys = try SecureSessionKeySchedule.frameKeys(
      sharedSecret: clientSecret,
      sessionTranscriptHash: transcriptHash,
      selection: CryptoFixtures.selection())
    let serverKeys = try SecureSessionKeySchedule.frameKeys(
      sharedSecret: serverSecret,
      sessionTranscriptHash: transcriptHash,
      selection: CryptoFixtures.selection())
    XCTAssertEqual(clientKeys.clientToServer, serverKeys.clientToServer)
    XCTAssertEqual(clientKeys.serverToClient, serverKeys.serverToClient)
  }

  func testKeysBindTheExactNegotiatedTuple() throws {
    let transcriptHash = try CryptoFixtures.sessionTranscript().canonicalHash()
    let baseline = try SecureSessionKeySchedule.frameKeys(
      inputKeyMaterial: CryptoFixtures.keyScheduleIKM,
      sessionTranscriptHash: transcriptHash,
      selection: CryptoFixtures.selection())

    let variants = [
      try CryptoFixtures.alternateMajorSelection(),
      try CryptoFixtures.alternateMinorSelection(),
      try CryptoFixtures.reducedFeatureSelection(),
    ]
    for variant in variants {
      let keys = try SecureSessionKeySchedule.frameKeys(
        inputKeyMaterial: CryptoFixtures.keyScheduleIKM,
        sessionTranscriptHash: transcriptHash,
        selection: variant)
      XCTAssertNotEqual(keys.clientToServer, baseline.clientToServer)
      XCTAssertNotEqual(keys.serverToClient, baseline.serverToClient)
    }
  }

  func testKeysBindTheTranscriptHashSalt() throws {
    let baseline = try CryptoFixtures.frameKeys()
    let otherHash = try CryptoFixtures.sessionTranscript(
      hostTLSSPKIFingerprint: CryptoFixtures.tlsNextSPKIFingerprint
    ).canonicalHash()
    let keys = try SecureSessionKeySchedule.frameKeys(
      inputKeyMaterial: CryptoFixtures.keyScheduleIKM,
      sessionTranscriptHash: otherHash,
      selection: CryptoFixtures.selection())
    XCTAssertNotEqual(keys.clientToServer, baseline.clientToServer)
    XCTAssertNotEqual(keys.serverToClient, baseline.serverToClient)
  }

  func testKeysBindTheInputKeyMaterial() throws {
    let baseline = try CryptoFixtures.frameKeys()
    let keys = try SecureSessionKeySchedule.frameKeys(
      inputKeyMaterial: SymmetricKey(data: Data(repeating: 0x4C, count: 32)),
      sessionTranscriptHash: try CryptoFixtures.sessionTranscript().canonicalHash(),
      selection: CryptoFixtures.selection())
    XCTAssertNotEqual(keys.clientToServer, baseline.clientToServer)
    XCTAssertNotEqual(keys.serverToClient, baseline.serverToClient)
  }

  func testWrongTranscriptHashLengthFailsClosed() {
    XCTAssertThrowsError(
      try SecureSessionKeySchedule.frameKeys(
        inputKeyMaterial: CryptoFixtures.keyScheduleIKM,
        sessionTranscriptHash: Data(repeating: 0x2A, count: 31),
        selection: CryptoFixtures.selection()
      ))
  }

  func testDirectionLabelsCarryDomainAndTuple() throws {
    let selection = try CryptoFixtures.selection()
    let clientLabel = SecureSessionKeySchedule.directionLabel(
      .frameKeyClientToServer, selection: selection)
    let serverLabel = SecureSessionKeySchedule.directionLabel(
      .frameKeyServerToClient, selection: selection)
    XCTAssertNotEqual(clientLabel, serverLabel)
    XCTAssertEqual(clientLabel.first, CanonicalStatementVersion.current)

    let clientDomain = Data(CanonicalStatementDomain.frameKeyClientToServer.rawValue.utf8)
    XCTAssertEqual(clientLabel.subdata(in: 3..<(3 + clientDomain.count)), clientDomain)

    let reducedLabel = SecureSessionKeySchedule.directionLabel(
      .frameKeyClientToServer, selection: try CryptoFixtures.reducedFeatureSelection())
    XCTAssertNotEqual(clientLabel, reducedLabel)
  }
}
