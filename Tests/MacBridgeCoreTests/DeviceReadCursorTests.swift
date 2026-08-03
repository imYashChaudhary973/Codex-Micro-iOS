import CompanionProtocol
import CryptoKit
import Foundation
import XCTest

@testable import MacBridgeCore

/// Step 2.8 read-cursor storage model: device-own, scoped, monotonic, and
/// persisted before it becomes visible. No network mutation exists yet.
final class DeviceReadCursorTests: XCTestCase {
  private let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
  private let otherDeviceID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!

  // MARK: - Device-own and scoped

  func testAdvanceAndReadBackAnInScopeThread() async throws {
    let world = try World(projects: ["project-a"])

    let cursor = try await world.store.advance(
      deviceID: deviceID, threadID: "thread-a", to: 7)

    XCTAssertEqual(cursor.readSequence, 7)
    XCTAssertEqual(cursor.updatedAtEpochSeconds, 1_000)
    let stored = try await world.store.cursor(deviceID: deviceID, threadID: "thread-a")
    XCTAssertEqual(stored, cursor)
  }

  func testOutOfScopeAndUnattributedThreadsAreNotAuthorized() async throws {
    let world = try World(projects: ["project-a"])

    for threadID in ["thread-secret", "thread-unattributed"] {
      await assertThrowsErrorAsync(
        try await world.store.advance(deviceID: deviceID, threadID: threadID, to: 1)
      ) { error in
        XCTAssertEqual(error as? DeviceReadCursorError, .notAuthorized)
      }
      await assertThrowsErrorAsync(
        try await world.store.cursor(deviceID: deviceID, threadID: threadID)
      ) { error in
        XCTAssertEqual(error as? DeviceReadCursorError, .notAuthorized)
      }
    }
  }

  func testANonObservableDeviceHasNoReadCursorAccess() async throws {
    let world = try World(projects: ["project-a"])
    world.scopes.set(.notObservable, for: deviceID)

    await assertThrowsErrorAsync(
      try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 1)
    ) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .notAuthorized)
    }
    await assertThrowsErrorAsync(try await world.store.cursors(deviceID: deviceID)) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .notAuthorized)
    }
  }

  func testOneDeviceCannotObserveAnotherDevicesPositions() async throws {
    let world = try World(projects: ["project-a"])
    world.scopes.set(
      .scoped(try World.scope(deviceID: otherDeviceID, projects: ["project-a"])),
      for: otherDeviceID)
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 9)

    let foreign = try await world.store.cursor(deviceID: otherDeviceID, threadID: "thread-a")
    let foreignList = try await world.store.cursors(deviceID: otherDeviceID)

    XCTAssertNil(foreign)
    XCTAssertEqual(foreignList, [])
  }

  func testListingIsRestrictedToThreadsCurrentlyInScope() async throws {
    let world = try World(projects: ["project-a", "project-b"])
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 1)
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-b", to: 2)

    world.scopes.set(
      .scoped(
        try World.scope(deviceID: deviceID, projects: ["project-a"], revision: 2, viewEpoch: 2)),
      for: deviceID)

    let visible = try await world.store.cursors(deviceID: deviceID)
    XCTAssertEqual(visible.map(\.threadID), ["thread-a"])
  }

  // MARK: - Monotonic

  func testPositionsOnlyMoveForward() async throws {
    let world = try World(projects: ["project-a"])
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 5)

    for regressing in [UInt64(1), 4, 5] {
      await assertThrowsErrorAsync(
        try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: regressing)
      ) { error in
        XCTAssertEqual(error as? DeviceReadCursorError, .notMonotonic)
      }
    }

    let advanced = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 6)
    XCTAssertEqual(advanced.readSequence, 6)
  }

  func testZeroAndFixedWidthPositionsFailClosed() async throws {
    let world = try World(projects: ["project-a"])

    for invalid in [UInt64(0), UInt64.max] {
      await assertThrowsErrorAsync(
        try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: invalid)
      ) { error in
        XCTAssertEqual(error as? DeviceReadCursorError, .counterOverflow)
      }
    }
  }

  func testPerDeviceThreadCeilingIsEnforced() async throws {
    let world = try World(projects: ["project-a"])
    for index in 0..<DeviceReadCursorLimits.maxThreadsPerDevice {
      let threadID = String(format: "thread-%04d", index)
      world.table.attribute(threadID: threadID, projectID: "project-a")
      _ = try await world.store.advance(deviceID: deviceID, threadID: threadID, to: 1)
    }
    world.table.attribute(threadID: "thread-overflow", projectID: "project-a")

    await assertThrowsErrorAsync(
      try await world.store.advance(deviceID: deviceID, threadID: "thread-overflow", to: 1)
    ) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .cursorLimitExceeded)
    }
  }

  // MARK: - Persistence

  func testStateSurvivesReopen() async throws {
    let storage = InMemoryReadCursorStorage()
    let world = try World(projects: ["project-a"], storage: storage)
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 4)

    let reopened = try DeviceReadCursorStore(
      storage: storage, scopes: world.scopes, attribution: world.table, clock: { 2_000 })
    let cursor = try await reopened.cursor(deviceID: deviceID, threadID: "thread-a")

    XCTAssertEqual(cursor?.readSequence, 4)
    let sequence = await reopened.writeSequence()
    XCTAssertEqual(sequence, 1)
  }

  func testFailedWriteLeavesThePriorStateInForce() async throws {
    let storage = FailableReadCursorStorage()
    let world = try World(projects: ["project-a"], storage: storage)
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 4)
    storage.failWrites = true

    await assertThrowsErrorAsync(
      try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 5)
    ) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .storageUnavailable)
    }

    let cursor = try await world.store.cursor(deviceID: deviceID, threadID: "thread-a")
    XCTAssertEqual(cursor?.readSequence, 4)
    let sequence = await world.store.writeSequence()
    XCTAssertEqual(sequence, 1)
  }

  func testCorruptPersistedStateFailsClosedAtOpen() throws {
    let storage = InMemoryReadCursorStorage()
    try storage.replace(blob: Data([0x00, 0x01, 0x02]))
    let scopes = FakeObservationScopeSource()

    XCTAssertThrowsError(
      try DeviceReadCursorStore(
        storage: storage, scopes: scopes, attribution: ThreadProjectTable(), clock: { 1_000 })
    ) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .corruptState)
    }
  }

  func testMissingStateIsAValidFreshInstall() async throws {
    let world = try World(projects: ["project-a"], storage: InMemoryReadCursorStorage())

    let sequence = await world.store.writeSequence()
    let cursors = try await world.store.cursors(deviceID: deviceID)

    XCTAssertEqual(sequence, 0)
    XCTAssertEqual(cursors, [])
  }

  // MARK: - Purge

  func testPurgeDropsEveryPositionADeviceHolds() async throws {
    let world = try World(projects: ["project-a"])
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 1)

    try await world.store.purge(deviceID: deviceID)

    let cursor = try await world.store.cursor(deviceID: deviceID, threadID: "thread-a")
    XCTAssertNil(cursor)
  }

  func testPurgingAnUnknownDeviceIsANoOpAndWritesNothing() async throws {
    let world = try World(projects: ["project-a"])

    try await world.store.purge(deviceID: otherDeviceID)

    let sequence = await world.store.writeSequence()
    XCTAssertEqual(sequence, 0)
  }

  func testScopeReductionPurgesOnlyTheNowUnauthorizedPositions() async throws {
    let world = try World(projects: ["project-a", "project-b"])
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-a", to: 1)
    _ = try await world.store.advance(deviceID: deviceID, threadID: "thread-b", to: 2)
    world.scopes.set(
      .scoped(
        try World.scope(deviceID: deviceID, projects: ["project-a"], revision: 2, viewEpoch: 2)),
      for: deviceID)

    let dropped = try await world.store.purgeOutOfScope(deviceID: deviceID)

    XCTAssertEqual(dropped, 1)
    let remaining = try await world.store.cursors(deviceID: deviceID)
    XCTAssertEqual(remaining.map(\.threadID), ["thread-a"])
    let second = try await world.store.purgeOutOfScope(deviceID: deviceID)
    XCTAssertEqual(second, 0)
  }

  // MARK: - Canonical blob

  func testBlobRoundTripsAndIsByteDeterministic() throws {
    let state = try sampleState()

    let encoded = try DeviceReadCursorBlobCodec.encode(state)
    let decoded = try DeviceReadCursorBlobCodec.decode(encoded)

    XCTAssertEqual(decoded, state)
    XCTAssertEqual(try DeviceReadCursorBlobCodec.encode(decoded), encoded)
  }

  func testBlobRejectsTruncationTrailingBytesWrongVersionAndForeignDomain() throws {
    let encoded = try DeviceReadCursorBlobCodec.encode(try sampleState())

    for cut in 0..<encoded.count {
      XCTAssertThrowsError(
        try DeviceReadCursorBlobCodec.decode(encoded.prefix(cut)), "truncation at \(cut)")
    }
    XCTAssertThrowsError(try DeviceReadCursorBlobCodec.decode(encoded + Data([0x00])))

    var wrongVersion = Data(encoded)
    wrongVersion[0] = 2
    XCTAssertThrowsError(try DeviceReadCursorBlobCodec.decode(wrongVersion))

    var foreignDomain = Data(encoded)
    foreignDomain[3] = foreignDomain[3] ^ 0xFF
    XCTAssertThrowsError(try DeviceReadCursorBlobCodec.decode(foreignDomain))
  }

  func testBlobRejectsNonCanonicalOrderingAndZeroWriteSequence() throws {
    let zeroSequence = DeviceReadCursorState(writeSequence: 0, cursors: [:])
    XCTAssertThrowsError(try DeviceReadCursorBlobCodec.encode(zeroSequence))

    // Two threads written in descending order must not decode.
    var blob = Data([DeviceReadCursorBlobCodec.version])
    let domain = Data(DeviceReadCursorBlobCodec.domain.utf8)
    blob.append(contentsOf: [UInt8(domain.count >> 8), UInt8(domain.count & 0xFF)])
    blob.append(domain)
    blob.append(Data(withUnsafeBytes(of: UInt64(1).bigEndian) { Array($0) }))
    blob.append(contentsOf: [0x00, 0x01])
    blob.append(withUnsafeBytes(of: deviceID.uuid) { Data($0) })
    blob.append(contentsOf: [0x00, 0x02])
    for threadID in ["thread-b", "thread-a"] {
      let bytes = Data(threadID.utf8)
      blob.append(contentsOf: [UInt8(bytes.count >> 8), UInt8(bytes.count & 0xFF)])
      blob.append(bytes)
      blob.append(Data(withUnsafeBytes(of: UInt64(1).bigEndian) { Array($0) }))
      blob.append(Data(withUnsafeBytes(of: UInt64(1_000).bigEndian) { Array($0) }))
    }

    XCTAssertThrowsError(try DeviceReadCursorBlobCodec.decode(blob)) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .corruptState)
    }
  }

  func testOversizedBlobIsRejectedBeforeDecoding() {
    let oversized = Data(repeating: 0x01, count: DeviceReadCursorLimits.maximumBlobByteCount + 1)

    XCTAssertThrowsError(try DeviceReadCursorBlobCodec.decode(oversized)) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .corruptState)
    }
  }

  func testRecordRejectsMalformedThreadIdentifiers() {
    let cases = ["", String(repeating: "t", count: 129), "thread\u{0007}a"]
    for threadID in cases {
      XCTAssertThrowsError(
        try DeviceReadCursor(
          deviceID: deviceID, threadID: threadID, readSequence: 1, updatedAtEpochSeconds: 1),
        threadID
      )
    }
  }

  // MARK: - Production file store

  func testFileStoreUsesOwnerOnlyPermissionsAndAtomicReplacement() throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-micro-read-cursors-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let fileURL = directory.appendingPathComponent("device-read-cursors.blob")
    let store = try FileBackedReadCursorStorage(fileURL: fileURL)

    XCTAssertNil(try store.load())
    let blob = try DeviceReadCursorBlobCodec.encode(try sampleState())
    try store.replace(blob: blob)

    XCTAssertEqual(try store.load(), blob)
    let fileAttributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
    let directoryAttributes = try FileManager.default.attributesOfItem(atPath: directory.path)
    XCTAssertEqual(fileAttributes[.posixPermissions] as? NSNumber, 0o600)
    XCTAssertEqual(directoryAttributes[.posixPermissions] as? NSNumber, 0o700)
    let excluded = try fileURL.resourceValues(forKeys: [.isExcludedFromBackupKey])
    XCTAssertEqual(excluded.isExcludedFromBackup, true)
  }

  func testFileStoreRefusesAnOversizedBlob() throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("codex-micro-read-cursors-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try FileBackedReadCursorStorage(
      fileURL: directory.appendingPathComponent("device-read-cursors.blob"))

    XCTAssertThrowsError(
      try store.replace(
        blob: Data(repeating: 0x01, count: DeviceReadCursorLimits.maximumBlobByteCount + 1))
    ) { error in
      XCTAssertEqual(error as? DeviceReadCursorError, .cursorLimitExceeded)
    }
  }

  // MARK: - Fixtures

  private func sampleState() throws -> DeviceReadCursorState {
    DeviceReadCursorState(
      writeSequence: 3,
      cursors: [
        deviceID: [
          "thread-a": try DeviceReadCursor(
            deviceID: deviceID, threadID: "thread-a", readSequence: 4,
            updatedAtEpochSeconds: 1_000),
          "thread-b": try DeviceReadCursor(
            deviceID: deviceID, threadID: "thread-b", readSequence: 9,
            updatedAtEpochSeconds: 1_200),
        ],
        otherDeviceID: [
          "thread-c": try DeviceReadCursor(
            deviceID: otherDeviceID, threadID: "thread-c", readSequence: 1,
            updatedAtEpochSeconds: 900)
        ],
      ]
    )
  }

  private struct World {
    let store: DeviceReadCursorStore
    let scopes = FakeObservationScopeSource()
    let table = ThreadProjectTable()

    init(projects: Set<String>, storage: any DeviceReadCursorStorage = InMemoryReadCursorStorage())
      throws
    {
      let deviceID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
      table.attribute(threadID: "thread-a", projectID: "project-a")
      table.attribute(threadID: "thread-b", projectID: "project-b")
      table.attribute(threadID: "thread-secret", projectID: "project-secret")
      scopes.set(
        .scoped(try Self.scope(deviceID: deviceID, projects: projects)), for: deviceID)
      store = try DeviceReadCursorStore(
        storage: storage, scopes: scopes, attribution: table, clock: { 1_000 })
    }

    static func scope(
      deviceID: UUID,
      projects: Set<String>,
      revision: UInt64 = 1,
      viewEpoch: UInt64 = 1
    ) throws -> AuthorizedViewScope {
      AuthorizedViewScope(
        grant: try AuthoritativeDeviceGrant(
          deviceID: deviceID,
          devicePublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
          createdAtEpochSeconds: 100,
          lastSeenAtEpochSeconds: 100,
          capabilities: [.view],
          permittedProjectIDs: projects,
          actionProfileCeiling: .observe,
          grantRevision: revision,
          authorizedViewEpoch: viewEpoch,
          expiresAtEpochSeconds: nil,
          tombstone: nil
        )
      )
    }
  }
}

/// In-memory storage with an injectable write failure.
final class FailableReadCursorStorage: DeviceReadCursorStorage, @unchecked Sendable {
  private let lock = NSLock()
  private var blob: Data?
  private var writesFail = false

  var failWrites: Bool {
    get {
      lock.lock()
      defer { lock.unlock() }
      return writesFail
    }
    set {
      lock.lock()
      defer { lock.unlock() }
      writesFail = newValue
    }
  }

  func load() throws -> Data? {
    lock.lock()
    defer { lock.unlock() }
    return blob
  }

  func replace(blob: Data) throws {
    lock.lock()
    defer { lock.unlock() }
    if writesFail { throw DeviceReadCursorError.storageUnavailable }
    self.blob = blob
  }
}
