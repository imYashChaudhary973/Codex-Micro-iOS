import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

final class FrameCodecTests: XCTestCase {
  private func clientSealer() throws -> SecureFrameSealer {
    try SecureFrameSealer(
      key: CryptoFixtures.frameKeys().clientToServer,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer)
  }

  private func serverOpener() throws -> SecureFrameOpener {
    try SecureFrameOpener(
      key: CryptoFixtures.frameKeys().clientToServer,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer)
  }

  func testGoldenSealedFrames() throws {
    var sealer = try clientSealer()
    XCTAssertEqual(
      try sealer.seal(CryptoFixtures.framePlaintext0).hexFixture, GoldenVectors.frame0Hex)
    XCTAssertEqual(
      try sealer.seal(CryptoFixtures.framePlaintext1).hexFixture, GoldenVectors.frame1Hex)
  }

  func testClientSealsAndServerOpensGoldenFrames() throws {
    var opener = try serverOpener()
    XCTAssertEqual(
      try opener.open(Data(hexFixture: GoldenVectors.frame0Hex)), CryptoFixtures.framePlaintext0)
    XCTAssertEqual(
      try opener.open(Data(hexFixture: GoldenVectors.frame1Hex)), CryptoFixtures.framePlaintext1)
  }

  func testServerSealsAndClientOpensIndependently() throws {
    let keys = try CryptoFixtures.frameKeys()
    var serverSealer = try SecureFrameSealer(
      key: keys.serverToClient,
      connectionID: CryptoFixtures.connectionID,
      direction: .serverToClient)
    var clientOpener = try SecureFrameOpener(
      key: keys.serverToClient,
      connectionID: CryptoFixtures.connectionID,
      direction: .serverToClient)

    for payload in [CryptoFixtures.framePlaintext0, CryptoFixtures.framePlaintext1] {
      XCTAssertEqual(try clientOpener.open(serverSealer.seal(payload)), payload)
    }
  }

  func testCountersStartAtZeroAndAreExactlyNext() throws {
    var sealer = try clientSealer()
    var opener = try serverOpener()
    for expected: UInt64 in 0...3 {
      let frame = try sealer.seal(CryptoFixtures.framePlaintext0)
      let header = try SecureFrameHeader.decode(fromFrame: frame)
      XCTAssertEqual(header.counter, expected)
      XCTAssertEqual(try opener.open(frame), CryptoFixtures.framePlaintext0)
    }
  }

  func testHeaderEncodeDecodeRoundTrip() throws {
    let header = SecureFrameHeader(
      connectionID: CryptoFixtures.connectionID,
      direction: .serverToClient,
      counter: 0x0102_0304_0506_0708,
      ciphertextLength: 0x0000_1234
    )
    let encoded = header.encoded()
    XCTAssertEqual(encoded.count, SecureFrameHeader.headerByteCount)
    XCTAssertEqual(try SecureFrameHeader.decode(fromFrame: encoded), header)
  }

  func testHeaderLayoutIsVersionDirectionConnectionCounterLength() throws {
    let frame = Data(hexFixture: GoldenVectors.frame0Hex)
    XCTAssertEqual(frame[0], SecureFrameHeader.currentVersion)
    XCTAssertEqual(frame.subdata(in: 1..<5), Data("c2s1".utf8))
    XCTAssertEqual(
      frame.subdata(in: 5..<21), Data(repeating: 0x55, count: 16))
    XCTAssertEqual(frame.subdata(in: 21..<29), Data(count: 8))
    XCTAssertEqual(
      frame.subdata(in: 29..<33),
      Data([0x00, 0x00, 0x00, UInt8(CryptoFixtures.framePlaintext0.count)])
    )
    let overhead = SecureFrameHeader.headerByteCount + SecureFrameHeader.tagByteCount
    XCTAssertEqual(frame.count, overhead + CryptoFixtures.framePlaintext0.count)
  }

  func testNonceIsDirectionPrefixPlusBigEndianCounter() {
    let nonce = SecureFrameHeader.nonceBytes(direction: .clientToServer, counter: 0x0A0B)
    XCTAssertEqual(nonce.count, 12)
    XCTAssertEqual(nonce.prefix(4), Data("c2s1".utf8))
    XCTAssertEqual(nonce.suffix(8), Data([0, 0, 0, 0, 0, 0, 0x0A, 0x0B]))
    XCTAssertNotEqual(
      nonce.prefix(4),
      SecureFrameHeader.nonceBytes(direction: .serverToClient, counter: 0x0A0B).prefix(4)
    )
  }

  func testMaximumPlaintextRoundTrips() throws {
    var sealer = try clientSealer()
    var opener = try serverOpener()
    let payload = Data(repeating: 0x7E, count: SecureFrameHeader.maxPlaintextByteCount)
    let frame = try sealer.seal(payload)
    XCTAssertEqual(frame.count, SecureTransportLimits.maxMessageBytes)
    XCTAssertEqual(try opener.open(frame), payload)
  }

  func testDirectionalKeysAreNotInterchangeable() throws {
    let keys = try CryptoFixtures.frameKeys()
    var sealer = try SecureFrameSealer(
      key: keys.clientToServer,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer)
    var opener = try SecureFrameOpener(
      key: keys.serverToClient,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer)
    let frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    XCTAssertThrowsError(try opener.open(frame)) { error in
      XCTAssertEqual(error as? SecureFrameError, .authenticationFailed)
    }
  }
}
