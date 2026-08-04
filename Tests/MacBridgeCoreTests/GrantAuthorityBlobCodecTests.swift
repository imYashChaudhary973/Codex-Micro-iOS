import CompanionProtocol
import Foundation
import XCTest

@testable import MacBridgeCore

final class GrantAuthorityBlobCodecTests: XCTestCase {
  private let deviceID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!

  func testGoldenFixtureRoundTripsByteExactly() throws {
    let grant = try AuthoritativeDeviceGrant(
      deviceID: deviceID,
      devicePublicKey: Data(
        hexFixture:
          "041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b"
      ),
      createdAtEpochSeconds: 0x0102_0304_0506_0708,
      lastSeenAtEpochSeconds: 0x1112_1314_1516_1718,
      capabilities: [.interrupt, .view],
      permittedProjectIDs: ["project-a", "π"],
      actionProfileCeiling: .runReadOnly,
      grantRevision: 7,
      authorizedViewEpoch: 9,
      expiresAtEpochSeconds: 0x2122_2324_2526_2728,
      tombstone: nil
    )
    let state = GrantAuthorityState(
      hostGeneration: 3,
      authoritySequence: 5,
      grants: [deviceID: grant]
    )
    let expected = Data(
      hexFixture:
        "010025636f6465782d6d6963726f2f6465766963652d6772616e742d617574686f726974792f7631000000000000000300000000000000050001111111112222333344445555555555550041041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b0102030405060708111213141516171800020009696e746572727570740004766965770002000970726f6a6563742d610002cf80000b72756e526561644f6e6c790000000000000007000000000000000901212223242526272800"
    )

    let encoded = try GrantAuthorityBlobCodec.encode(state)
    XCTAssertEqual(encoded, expected)
    XCTAssertEqual(try GrantAuthorityBlobCodec.decode(expected), state)
    XCTAssertEqual(
      try GrantAuthorityBlobCodec.encode(GrantAuthorityBlobCodec.decode(expected)),
      expected
    )
  }

  func testCanonicalEncodingOrdersDevicesCapabilitiesAndProjects() throws {
    let lowerID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    let upperID = UUID(uuidString: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")!
    let lower = try fixtureGrant(
      deviceID: lowerID,
      capabilities: [.view, .interrupt],
      projects: ["z", "a"]
    )
    let upper = try fixtureGrant(
      deviceID: upperID,
      capabilities: [.view],
      projects: []
    )
    let first = GrantAuthorityState(
      hostGeneration: 1,
      authoritySequence: 1,
      grants: [upperID: upper, lowerID: lower]
    )
    let second = GrantAuthorityState(
      hostGeneration: 1,
      authoritySequence: 1,
      grants: [lowerID: lower, upperID: upper]
    )

    XCTAssertEqual(
      try GrantAuthorityBlobCodec.encode(first),
      try GrantAuthorityBlobCodec.encode(second)
    )
  }

  func testWrongVersionAndDomainFailClosed() throws {
    let valid = try fixtureBlob()
    var wrongVersion = valid
    wrongVersion[0] = 2
    assertCorrupt(wrongVersion)

    var wrongDomain = valid
    wrongDomain[3] ^= 0x01
    assertCorrupt(wrongDomain)
  }

  func testEveryTruncationFailsClosed() throws {
    let valid = try fixtureBlob()
    for count in 0..<valid.count {
      assertCorrupt(Data(valid.prefix(count)), file: #filePath, line: #line)
    }
  }

  func testTrailingBytesFailClosed() throws {
    var valid = try fixtureBlob()
    valid.append(0)
    assertCorrupt(valid)
  }

  func testPatchedVariableLengthFailsClosed() throws {
    var valid = try fixtureBlob()
    valid[1] = 0xff
    valid[2] = 0xff
    assertCorrupt(valid)
  }

  func testDuplicateDeviceIDsFailClosed() throws {
    let firstID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    let secondID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    let first = try fixtureGrant(deviceID: firstID)
    let second = try fixtureGrant(deviceID: secondID)
    var blob = try GrantAuthorityBlobCodec.encode(
      GrantAuthorityState(
        hostGeneration: 1,
        authoritySequence: 1,
        grants: [firstID: first, secondID: second]
      ))
    let secondBytes = uuidBytes(secondID)
    let range = try XCTUnwrap(blob.range(of: secondBytes))
    blob.replaceSubrange(range, with: uuidBytes(firstID))

    assertCorrupt(blob)
  }

  func testOversizedBlobFailsClosedOnDecode() {
    assertCorrupt(Data(repeating: 0, count: GrantAuthorityLimits.maximumBlobByteCount + 1))
  }

  func testZeroHostGenerationAndSequenceFailClosed() throws {
    var blob = try fixtureBlob()
    let generationOffset = 1 + 2 + GrantAuthorityBlobCodec.domain.utf8.count
    blob.replaceSubrange(
      generationOffset..<(generationOffset + 8), with: Data(repeating: 0, count: 8))
    assertCorrupt(blob)

    blob = try fixtureBlob()
    let sequenceOffset = generationOffset + 8
    blob.replaceSubrange(sequenceOffset..<(sequenceOffset + 8), with: Data(repeating: 0, count: 8))
    assertCorrupt(blob)
  }

  func testRecordValidationRejectsMalformedKeyAndTimestamps() {
    XCTAssertThrowsError(
      try fixtureGrant(deviceID: deviceID, publicKey: Data(repeating: 0x04, count: 64))
    ) { XCTAssertEqual($0 as? DeviceGrantAuthorityError, .invalidGrant) }
    XCTAssertThrowsError(
      try fixtureGrant(deviceID: deviceID, publicKey: Data(repeating: 0x03, count: 65))
    ) { XCTAssertEqual($0 as? DeviceGrantAuthorityError, .invalidGrant) }
    XCTAssertThrowsError(
      try fixtureGrant(
        deviceID: deviceID,
        publicKey: Data([0x04] + Array(repeating: 0x00, count: 64))
      )
    ) { XCTAssertEqual($0 as? DeviceGrantAuthorityError, .invalidGrant) }
    XCTAssertThrowsError(
      try AuthoritativeDeviceGrant(
        deviceID: deviceID,
        devicePublicKey: validPublicKey(),
        createdAtEpochSeconds: 10,
        lastSeenAtEpochSeconds: 9,
        capabilities: [.view],
        permittedProjectIDs: [],
        actionProfileCeiling: .observe,
        grantRevision: 1,
        authorizedViewEpoch: 1,
        expiresAtEpochSeconds: nil,
        tombstone: nil
      )
    ) { XCTAssertEqual($0 as? DeviceGrantAuthorityError, .invalidGrant) }
  }

  func testProjectIDsRequireCanonicalUnicodeEncoding() {
    let decomposed = "e\u{301}"
    XCTAssertNotEqual(
      Data(decomposed.utf8),
      Data(decomposed.precomposedStringWithCanonicalMapping.utf8)
    )
    XCTAssertThrowsError(
      try fixtureGrant(deviceID: deviceID, projects: [decomposed])
    ) { XCTAssertEqual($0 as? DeviceGrantAuthorityError, .invalidGrant) }
  }

  func testInMemoryStoreDistinguishesExplicitEmptyFromMissing() throws {
    let store = InMemoryGrantAuthorityStore()
    XCTAssertEqual(try store.load(), .empty)

    let blob = Data([0x01])
    try store.replace(blob: blob)
    XCTAssertEqual(try store.load(), .blob(blob))

    try store.replace(blob: Data())
    XCTAssertEqual(try store.load(), .empty)

    store.clear()
    XCTAssertThrowsError(try store.load()) {
      XCTAssertEqual($0 as? DeviceGrantAuthorityError, .authorityMissing)
    }
  }

  private func fixtureBlob() throws -> Data {
    let grant = try fixtureGrant(deviceID: deviceID)
    return try GrantAuthorityBlobCodec.encode(
      GrantAuthorityState(
        hostGeneration: 1,
        authoritySequence: 1,
        grants: [deviceID: grant]
      ))
  }

  private func fixtureGrant(
    deviceID: UUID,
    publicKey: Data? = nil,
    capabilities: Set<DeviceCapability> = [.view],
    projects: Set<String> = []
  ) throws -> AuthoritativeDeviceGrant {
    try AuthoritativeDeviceGrant(
      deviceID: deviceID,
      devicePublicKey: publicKey ?? validPublicKey(),
      createdAtEpochSeconds: 100,
      lastSeenAtEpochSeconds: 100,
      capabilities: capabilities,
      permittedProjectIDs: projects,
      actionProfileCeiling: .observe,
      grantRevision: 1,
      authorizedViewEpoch: 1,
      expiresAtEpochSeconds: nil,
      tombstone: nil
    )
  }

  private func validPublicKey() -> Data {
    Data(
      hexFixture:
        "041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b"
    )
  }

  private func uuidBytes(_ id: UUID) -> Data {
    withUnsafeBytes(of: id.uuid) { Data($0) }
  }

  private func assertCorrupt(
    _ blob: Data,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertThrowsError(
      try GrantAuthorityBlobCodec.decode(blob),
      file: file,
      line: line
    ) {
      XCTAssertEqual(
        $0 as? DeviceGrantAuthorityError,
        .corruptAuthority,
        file: file,
        line: line
      )
    }
  }
}

extension Data {
  fileprivate init(hexFixture: String) {
    precondition(hexFixture.count.isMultiple(of: 2))
    var bytes = [UInt8]()
    bytes.reserveCapacity(hexFixture.count / 2)
    var iterator = hexFixture.makeIterator()
    while let high = iterator.next(), let low = iterator.next() {
      bytes.append(UInt8(String([high, low]), radix: 16)!)
    }
    self.init(bytes)
  }
}
