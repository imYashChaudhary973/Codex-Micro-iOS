import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import CompanionCrypto

final class FrameCodecAdversarialTests: XCTestCase {
  private func makePair(
    connectionID: UUID = CryptoFixtures.connectionID
  ) throws -> (sealer: SecureFrameSealer, opener: SecureFrameOpener) {
    let key = try CryptoFixtures.frameKeys().clientToServer
    return (
      try SecureFrameSealer(key: key, connectionID: connectionID, direction: .clientToServer),
      try SecureFrameOpener(key: key, connectionID: connectionID, direction: .clientToServer)
    )
  }

  private func assertOpenFails(
    _ frame: Data,
    with expected: SecureFrameError,
    file: StaticString = #filePath,
    line: UInt = #line
  ) throws {
    var (_, opener) = try makePair()
    XCTAssertThrowsError(try opener.open(frame), file: file, line: line) { error in
      XCTAssertEqual(error as? SecureFrameError, expected, file: file, line: line)
    }
  }

  func testReflectedFrameIsRejected() throws {
    // The server's own server-to-client frame echoed back to the server's
    // client-to-server opener must fail on the direction prefix.
    let keys = try CryptoFixtures.frameKeys()
    var serverSealer = try SecureFrameSealer(
      key: keys.serverToClient,
      connectionID: CryptoFixtures.connectionID,
      direction: .serverToClient)
    let reflected = try serverSealer.seal(CryptoFixtures.framePlaintext0)
    try assertOpenFails(reflected, with: .invalidDirection)
  }

  func testEveryTamperedHeaderByteIsRejected() throws {
    var (sealer, _) = try makePair()
    let frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    for index in 0..<SecureFrameHeader.headerByteCount {
      var tampered = frame
      tampered[index] ^= 0x01
      var (_, opener) = try makePair()
      XCTAssertThrowsError(
        try opener.open(tampered), "tampered header byte \(index) must be rejected")
    }
  }

  func testTamperedHeaderRegionsFailWithClosedReasons() throws {
    var (sealer, _) = try makePair()
    let frame = try sealer.seal(CryptoFixtures.framePlaintext0)

    var version = frame
    version[0] = 0x02
    try assertOpenFails(version, with: .invalidVersion)

    var direction = frame
    direction[1] = 0x78
    try assertOpenFails(direction, with: .invalidDirection)

    var connection = frame
    connection[5] ^= 0xFF
    try assertOpenFails(connection, with: .connectionMismatch)

    var counter = frame
    counter[28] ^= 0x01
    try assertOpenFails(counter, with: .counterGap)

    var length = frame
    length[32] ^= 0x01
    try assertOpenFails(length, with: .invalidLength)
  }

  func testTamperedCiphertextIsRejected() throws {
    var (sealer, _) = try makePair()
    var frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    frame[SecureFrameHeader.headerByteCount + 3] ^= 0x01
    try assertOpenFails(frame, with: .authenticationFailed)
  }

  func testTamperedTagIsRejected() throws {
    var (sealer, _) = try makePair()
    var frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    frame[frame.count - 1] ^= 0x01
    try assertOpenFails(frame, with: .authenticationFailed)
  }

  func testDuplicateFrameIsRejected() throws {
    var (sealer, opener) = try makePair()
    let frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    XCTAssertEqual(try opener.open(frame), CryptoFixtures.framePlaintext0)
    XCTAssertThrowsError(try opener.open(frame)) { error in
      XCTAssertEqual(error as? SecureFrameError, .duplicateCounter)
    }
  }

  func testCounterGapIsRejected() throws {
    var (sealer, opener) = try makePair()
    let frame0 = try sealer.seal(CryptoFixtures.framePlaintext0)
    _ = try sealer.seal(CryptoFixtures.framePlaintext0)
    let frame2 = try sealer.seal(CryptoFixtures.framePlaintext1)
    XCTAssertEqual(try opener.open(frame0), CryptoFixtures.framePlaintext0)
    XCTAssertThrowsError(try opener.open(frame2)) { error in
      XCTAssertEqual(error as? SecureFrameError, .counterGap)
    }
  }

  func testCrossConnectionReplayIsRejected() throws {
    var (sealer, _) = try makePair(connectionID: CryptoFixtures.otherConnectionID)
    let foreign = try sealer.seal(CryptoFixtures.framePlaintext0)
    try assertOpenFails(foreign, with: .connectionMismatch)
  }

  func testSenderRefusesToSealPastMaxCounter() throws {
    let key = try CryptoFixtures.frameKeys().clientToServer
    var lastValid = try SecureFrameSealer(
      key: key,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      nextCounter: SecureFrameHeader.maxCounter)
    let frame = try lastValid.seal(CryptoFixtures.framePlaintext0)
    XCTAssertEqual(
      try SecureFrameHeader.decode(fromFrame: frame).counter, SecureFrameHeader.maxCounter)
    XCTAssertThrowsError(try lastValid.seal(CryptoFixtures.framePlaintext0)) { error in
      XCTAssertEqual(error as? SecureFrameError, .counterExhausted)
    }

    var exhausted = try SecureFrameSealer(
      key: key,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      nextCounter: .max)
    XCTAssertThrowsError(try exhausted.seal(CryptoFixtures.framePlaintext0)) { error in
      XCTAssertEqual(error as? SecureFrameError, .counterExhausted)
    }
  }

  func testReceiverFailsClosedBeforeCounterWrap() throws {
    let key = try CryptoFixtures.frameKeys().clientToServer
    var sealer = try SecureFrameSealer(
      key: key,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      nextCounter: SecureFrameHeader.maxCounter)
    let lastFrame = try sealer.seal(CryptoFixtures.framePlaintext0)

    var opener = try SecureFrameOpener(
      key: key,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      expectedCounter: SecureFrameHeader.maxCounter)
    XCTAssertEqual(try opener.open(lastFrame), CryptoFixtures.framePlaintext0)
    XCTAssertThrowsError(try opener.open(lastFrame)) { error in
      XCTAssertEqual(error as? SecureFrameError, .counterExhausted)
    }
  }

  func testHeaderCounterAtOverflowSentinelIsRejected() throws {
    var header = SecureFrameHeader(
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      counter: .max,
      ciphertextLength: 26
    ).encoded()
    header.append(Data(count: 26 + SecureFrameHeader.tagByteCount))
    try assertOpenFails(header, with: .counterExhausted)
  }

  func testTruncatedFramesAreRejected() throws {
    var (sealer, _) = try makePair()
    let frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    try assertOpenFails(Data(), with: .invalidLength)
    try assertOpenFails(frame.prefix(SecureFrameHeader.headerByteCount - 1), with: .invalidLength)
    try assertOpenFails(frame.dropLast(), with: .invalidLength)
    try assertOpenFails(frame.prefix(SecureFrameHeader.headerByteCount), with: .invalidLength)
  }

  func testOversizedFramesAreRejected() throws {
    var (sealer, _) = try makePair()
    let frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    try assertOpenFails(frame + Data([0x00]), with: .invalidLength)

    var oversized = SecureFrameHeader(
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      counter: 0,
      ciphertextLength: UInt32(SecureFrameHeader.maxPlaintextByteCount + 1)
    ).encoded()
    oversized.append(
      Data(count: SecureFrameHeader.maxPlaintextByteCount + 1 + SecureFrameHeader.tagByteCount))
    try assertOpenFails(oversized, with: .invalidLength)
  }

  func testZeroLengthCiphertextIsRejected() throws {
    var frame = SecureFrameHeader(
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      counter: 0,
      ciphertextLength: 0
    ).encoded()
    frame.append(Data(count: SecureFrameHeader.tagByteCount))
    try assertOpenFails(frame, with: .invalidLength)
  }

  func testWrongKeyIsRejected() throws {
    var (sealer, _) = try makePair()
    let frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    var opener = try SecureFrameOpener(
      key: SymmetricKey(data: Data(repeating: 0x11, count: 32)),
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer)
    XCTAssertThrowsError(try opener.open(frame)) { error in
      XCTAssertEqual(error as? SecureFrameError, .authenticationFailed)
    }
  }

  func testHeaderIsAuthenticatedAsAAD() throws {
    // Re-sealing the same plaintext under a different connection ID and
    // grafting the original header onto its ciphertext must fail: the AAD
    // no longer matches the sealed header.
    var (sealerA, _) = try makePair()
    let frameA = try sealerA.seal(CryptoFixtures.framePlaintext0)
    var sealerB = try SecureFrameSealer(
      key: CryptoFixtures.frameKeys().clientToServer,
      connectionID: CryptoFixtures.otherConnectionID,
      direction: .clientToServer)
    let frameB = try sealerB.seal(CryptoFixtures.framePlaintext0)

    let grafted =
      frameA.prefix(SecureFrameHeader.headerByteCount)
      + frameB.suffix(from: SecureFrameHeader.headerByteCount)
    try assertOpenFails(Data(grafted), with: .authenticationFailed)
  }

  func testUnknownDirectionPrefixIsRejected() throws {
    var (sealer, _) = try makePair()
    var frame = try sealer.seal(CryptoFixtures.framePlaintext0)
    frame.replaceSubrange(1..<5, with: Data("x9z9".utf8))
    try assertOpenFails(frame, with: .invalidDirection)
  }

  func testOpenerFailsClosedPermanentlyAfterAnyViolation() throws {
    var (sealer, opener) = try makePair()
    let frame0 = try sealer.seal(CryptoFixtures.framePlaintext0)
    var tampered = frame0
    tampered[frame0.count - 1] ^= 0x01
    XCTAssertThrowsError(try opener.open(tampered))
    XCTAssertThrowsError(try opener.open(frame0)) { error in
      XCTAssertEqual(error as? SecureFrameError, .sessionClosed)
    }
  }

  func testSealerFailsClosedPermanentlyAfterExhaustion() throws {
    var sealer = try SecureFrameSealer(
      key: CryptoFixtures.frameKeys().clientToServer,
      connectionID: CryptoFixtures.connectionID,
      direction: .clientToServer,
      nextCounter: .max)
    XCTAssertThrowsError(try sealer.seal(CryptoFixtures.framePlaintext0))
    XCTAssertThrowsError(try sealer.seal(CryptoFixtures.framePlaintext0)) { error in
      XCTAssertEqual(error as? SecureFrameError, .sessionClosed)
    }
  }

  func testSealerRejectsOutOfBoundsPlaintext() throws {
    var (sealer, _) = try makePair()
    XCTAssertThrowsError(try sealer.seal(Data())) { error in
      XCTAssertEqual(error as? SecureFrameError, .invalidPlaintextLength)
    }

    var (oversizedSealer, _) = try makePair()
    let oversized = Data(count: SecureFrameHeader.maxPlaintextByteCount + 1)
    XCTAssertThrowsError(try oversizedSealer.seal(oversized)) { error in
      XCTAssertEqual(error as? SecureFrameError, .invalidPlaintextLength)
    }
  }

  func testWrongKeyLengthFailsClosedAtConstruction() {
    let shortKey = SymmetricKey(data: Data(repeating: 0x22, count: 16))
    XCTAssertThrowsError(
      try SecureFrameSealer(
        key: shortKey, connectionID: CryptoFixtures.connectionID, direction: .clientToServer)
    ) { error in
      XCTAssertEqual(error as? SecureFrameError, .invalidKeyLength)
    }
    XCTAssertThrowsError(
      try SecureFrameOpener(
        key: shortKey, connectionID: CryptoFixtures.connectionID, direction: .clientToServer)
    ) { error in
      XCTAssertEqual(error as? SecureFrameError, .invalidKeyLength)
    }
  }
}
