import Foundation
import XCTest

@testable import MacBridgeServer

/// Deterministic in-memory rotation-state storage with injectable
/// failures.
final class InMemoryRotationStateStorage: TLSRotationStateStorage {
  var blob: Data?
  var readError: TLSRotationStateError?
  var writeError: TLSRotationStateError?

  func readBlob() throws -> Data? {
    if let readError { throw readError }
    return blob
  }

  func writeBlob(_ blob: Data) throws {
    if let writeError { throw writeError }
    self.blob = blob
  }
}

final class TLSRotationStateTests: XCTestCase {
  private let fingerprintA = Data(repeating: 0xA1, count: 32)
  private let fingerprintB = Data(repeating: 0xB2, count: 32)

  private func assertThrows<T>(
    _ expected: TLSRotationStateError,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> T
  ) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
      XCTAssertEqual(error as? TLSRotationStateError, expected, file: file, line: line)
    }
  }

  // MARK: - Record validation

  func testBaselineStateRequiresNoPreviousFingerprint() throws {
    let baseline = try TLSRotationState(
      rotationGeneration: 0, currentSPKIFingerprint: fingerprintA, previousSPKIFingerprint: nil)
    XCTAssertEqual(baseline.rotationGeneration, 0)
    assertThrows(.corruptState) {
      try TLSRotationState(
        rotationGeneration: 0,
        currentSPKIFingerprint: self.fingerprintA,
        previousSPKIFingerprint: self.fingerprintB
      )
    }
  }

  func testAdvancedStateRequiresDistinctPreviousFingerprint() throws {
    _ = try TLSRotationState(
      rotationGeneration: 1,
      currentSPKIFingerprint: fingerprintB,
      previousSPKIFingerprint: fingerprintA
    )
    assertThrows(.corruptState) {
      try TLSRotationState(
        rotationGeneration: 1, currentSPKIFingerprint: self.fingerprintB,
        previousSPKIFingerprint: nil)
    }
    assertThrows(.corruptState) {
      try TLSRotationState(
        rotationGeneration: 1,
        currentSPKIFingerprint: self.fingerprintB,
        previousSPKIFingerprint: self.fingerprintB
      )
    }
  }

  func testFingerprintLengthsAreExact() {
    assertThrows(.corruptState) {
      try TLSRotationState(
        rotationGeneration: 0,
        currentSPKIFingerprint: Data(repeating: 0xA1, count: 31),
        previousSPKIFingerprint: nil
      )
    }
    assertThrows(.corruptState) {
      try TLSRotationState(
        rotationGeneration: 1,
        currentSPKIFingerprint: self.fingerprintB,
        previousSPKIFingerprint: Data(repeating: 0xA1, count: 33)
      )
    }
  }

  // MARK: - Canonical blob codec

  func testCodecRoundTripsBaselineAndAdvancedStates() throws {
    let baseline = try TLSRotationState(
      rotationGeneration: 0, currentSPKIFingerprint: fingerprintA, previousSPKIFingerprint: nil)
    XCTAssertEqual(
      try TLSRotationStateBlobCodec.decode(TLSRotationStateBlobCodec.encode(baseline)), baseline)

    let advanced = try TLSRotationState(
      rotationGeneration: 7,
      currentSPKIFingerprint: fingerprintB,
      previousSPKIFingerprint: fingerprintA
    )
    XCTAssertEqual(
      try TLSRotationStateBlobCodec.decode(TLSRotationStateBlobCodec.encode(advanced)), advanced)
  }

  func testEveryTruncationFailsClosed() throws {
    let state = try TLSRotationState(
      rotationGeneration: 3,
      currentSPKIFingerprint: fingerprintB,
      previousSPKIFingerprint: fingerprintA
    )
    let blob = TLSRotationStateBlobCodec.encode(state)
    for length in 0..<blob.count {
      assertThrows(.corruptState) {
        try TLSRotationStateBlobCodec.decode(blob.prefix(length))
      }
    }
  }

  func testTrailingBytesFailClosed() throws {
    let state = try TLSRotationState(
      rotationGeneration: 0, currentSPKIFingerprint: fingerprintA, previousSPKIFingerprint: nil)
    var blob = TLSRotationStateBlobCodec.encode(state)
    blob.append(0)
    assertThrows(.corruptState) { try TLSRotationStateBlobCodec.decode(blob) }
  }

  func testWrongVersionAndDomainFailClosed() throws {
    let state = try TLSRotationState(
      rotationGeneration: 0, currentSPKIFingerprint: fingerprintA, previousSPKIFingerprint: nil)
    var wrongVersion = TLSRotationStateBlobCodec.encode(state)
    wrongVersion[0] = 2
    assertThrows(.corruptState) { try TLSRotationStateBlobCodec.decode(wrongVersion) }

    var wrongDomain = TLSRotationStateBlobCodec.encode(state)
    wrongDomain[4] ^= 0xFF
    assertThrows(.corruptState) { try TLSRotationStateBlobCodec.decode(wrongDomain) }
  }

  func testUnknownPresenceByteAndOversizedBlobFailClosed() throws {
    let state = try TLSRotationState(
      rotationGeneration: 0, currentSPKIFingerprint: fingerprintA, previousSPKIFingerprint: nil)
    var blob = TLSRotationStateBlobCodec.encode(state)
    blob[blob.count - 1] = 2
    assertThrows(.corruptState) { try TLSRotationStateBlobCodec.decode(blob) }

    assertThrows(.corruptState) {
      try TLSRotationStateBlobCodec.decode(
        Data(repeating: 0, count: TLSRotationStateBlobCodec.maximumBlobByteCount + 1))
    }
  }

  // MARK: - File-backed store

  private func makeTemporaryDirectory() -> URL {
    FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-micro-tests", isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
  }

  func testFileStoreRoundTripsBlobAtomically() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try FileBackedRotationStateStore(directoryURL: directory)
    XCTAssertNil(try store.readBlob())

    let state = try TLSRotationState(
      rotationGeneration: 4,
      currentSPKIFingerprint: fingerprintB,
      previousSPKIFingerprint: fingerprintA
    )
    let blob = TLSRotationStateBlobCodec.encode(state)
    try store.writeBlob(blob)
    XCTAssertEqual(try store.readBlob(), blob)

    let reopened = try FileBackedRotationStateStore(directoryURL: directory)
    XCTAssertEqual(try reopened.readBlob(), blob)
  }

  func testFileStoreAppliesFileProtections() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try FileBackedRotationStateStore(directoryURL: directory)
    try store.writeBlob(Data([1, 2, 3]))

    let fileURL = directory.appendingPathComponent("tls-rotation-state.v1.bin")
    let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.int16Value, 0o600)

    let values = try fileURL.resourceValues(forKeys: [.isExcludedFromBackupKey])
    XCTAssertEqual(values.isExcludedFromBackup, true)

    let directoryAttributes = try FileManager.default.attributesOfItem(atPath: directory.path)
    XCTAssertEqual(
      (directoryAttributes[.posixPermissions] as? NSNumber)?.int16Value, 0o700)
  }

  func testFileStoreRejectsOversizedPersistedBlob() throws {
    let directory = makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try FileBackedRotationStateStore(directoryURL: directory)
    let fileURL = directory.appendingPathComponent("tls-rotation-state.v1.bin")
    try Data(repeating: 0, count: TLSRotationStateBlobCodec.maximumBlobByteCount + 1)
      .write(to: fileURL)
    assertThrows(.corruptState) { try store.readBlob() }
  }
}
