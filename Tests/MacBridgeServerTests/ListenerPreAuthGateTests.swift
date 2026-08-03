import CompanionProtocol
import Foundation
import NIOCore
import NIOEmbedded
import XCTest

@testable import MacBridgeServer

/// Pre-authentication allowlist and gate behaviour (plan §7 gate 2).
///
/// Every refusal must be the same content-neutral reason, and nothing on
/// this path may disclose application state — the transport holds none.
final class ListenerPreAuthGateTests: XCTestCase {
  private let allowlist = ListenerPreAuthAllowlist()

  private func classify(_ data: Data) -> ListenerPreAuthDecision {
    allowlist.classify(data)
  }

  func testExactlyTheFourDeviceOriginatedKindsAreAllowlisted() {
    XCTAssertEqual(
      ListenerPreAuthAllowlist.allowedInboundKinds,
      [.pairingRequest, .pairingConfirmation, .sessionAuthRequest, .sessionAuthConfirmation]
    )
    XCTAssertEqual(ListenerHandshakeKind.allCases.count, 7)
  }

  func testEachAllowlistedKindIsAccepted() throws {
    for kind in ListenerPreAuthAllowlist.allowedInboundKinds {
      let encoded = try HandshakeFixture.envelope(kind: kind)
      guard case .allowed(let envelope) = classify(encoded) else {
        return XCTFail("\(kind) must be allowed")
      }
      XCTAssertEqual(envelope.kind, kind)
    }
  }

  func testHostOriginatedKindsAreRefusedInbound() throws {
    for kind in [ListenerHandshakeKind.pairingResponse, .sessionAuthResponse, .closeNotice] {
      let encoded = try HandshakeFixture.envelope(kind: kind)
      XCTAssertEqual(
        classify(encoded),
        .refused(ListenerPreAuthAllowlist.collapsedRefusal),
        "\(kind) must never be accepted inbound"
      )
    }
  }

  func testMalformedAndApplicationMessagesShareOneCollapsedRefusal() throws {
    let cursor = ReplayCursorEnvelope(
      deviceID: UUID(),
      grantRevision: 1,
      authorizedViewEpoch: 1,
      journalEpoch: try JournalEpoch(rawBytes: Data(repeating: 0x11, count: 16)),
      sequence: 1
    )
    let subscribe = SecureObservationSubscribe(subscriptionID: UUID(), resumeCursor: cursor)
    let denied: [Data] = [
      Data(),
      Data([0x00, 0x01, 0x02]),
      Data("not json".utf8),
      Data(#"{"kind":"pairingRequest"}"#.utf8),
      Data(#"{"payload":"AAAA"}"#.utf8),
      Data(#"{"kind":"applicationCommand","payload":"AAAA"}"#.utf8),
      Data(#"{"kind":"pairingRequest","payload":"AAAA","extra":1}"#.utf8),
      Data(#"{"kind":"pairingRequest","payload":""}"#.utf8),
      try JSONEncoder().encode(subscribe),
      Data(#"{"kind":"PairingRequest","payload":"AAAA"}"#.utf8),
      Data(#"[{"kind":"pairingRequest","payload":"AAAA"}]"#.utf8),
      Data(#"{"kind":1,"payload":"AAAA"}"#.utf8),
      Data(
        #"{"kind":"pairingRequest","payload":""#.utf8
          + Data(
            Data(repeating: 0x01, count: ListenerHandshakeEnvelope.maxPayloadBytes + 1)
              .base64EncodedString().utf8) + Data(#""}"#.utf8)),
    ]
    var reasons = Set<SecureCloseReason>()
    for payload in denied {
      guard case .refused(let reason) = classify(payload) else {
        return XCTFail("payload must be refused")
      }
      reasons.insert(reason)
    }
    XCTAssertEqual(reasons, [ListenerPreAuthAllowlist.collapsedRefusal])
  }

  func testOversizedHandshakeBodiesAreUnrepresentableAndRefused() throws {
    XCTAssertThrowsError(
      try ListenerHandshakeEnvelope(
        kind: .pairingRequest,
        payload: Data(repeating: 0x01, count: ListenerHandshakeEnvelope.maxPayloadBytes + 1)
      ))
    XCTAssertThrowsError(
      try ListenerHandshakeEnvelope(kind: .pairingRequest, payload: Data()))
    let oversized = Data(
      #"{"kind":"pairingRequest","payload":""#.utf8
        + Data(repeating: 0x41, count: 20_000) + Data(#""}"#.utf8))
    XCTAssertEqual(classify(oversized), .refused(ListenerPreAuthAllowlist.collapsedRefusal))
  }

  func testRefusalWritesExactlyOneClosedReasonAndNothingElse() throws {
    let controller = ListenerAdmissionController(ceilings: ListenerCeilings())
    guard case .success(let ticket) = controller.admit(source: .init(numericAddress: "10.0.0.5"))
    else {
      return XCTFail("expected admission")
    }
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerHandshakeGateHandler(
        connectionID: UUID(),
        source: .init(numericAddress: "10.0.0.5"),
        admission: controller,
        ticket: ticket,
        handshake: ScriptedHandshakeHandler(),
        authenticationDeadline: .seconds(20),
        logger: DiscardingListenerLogger()
      ))

    var buffer = channel.allocator.buffer(capacity: 16)
    buffer.writeBytes(Data(#"{"kind":"applicationCommand","payload":"AAAA"}"#.utf8))
    try channel.writeInbound(buffer)

    let written = try XCTUnwrap(try channel.readOutbound(as: ByteBuffer.self))
    let bytes = Data(written.readableBytesView)
    let envelope = try ListenerHandshakeEnvelope.decode(bytes)
    XCTAssertEqual(envelope.kind, .closeNotice)
    let notice = try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload)
    XCTAssertEqual(notice.reason, ListenerPreAuthAllowlist.collapsedRefusal)

    let object = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: envelope.payload) as? [String: Any])
    XCTAssertEqual(Set(object.keys), ["reason"])
    XCTAssertFalse(channel.isActive)
  }

  func testExhaustedPairingCeilingRefusesWithTheCollapsedReasonAndCloses() throws {
    let ceilings = ListenerCeilings()
    let controller = ListenerAdmissionController(ceilings: ceilings)
    let source = ListenerSourceKey(numericAddress: "10.0.0.6")
    for _ in 0..<ceilings.maxPairingAttemptsPerSourcePerMinute {
      XCTAssertTrue(controller.admitHandshakeMessage(.pairingRequest, source: source))
    }
    guard case .success(let ticket) = controller.admit(source: source) else {
      return XCTFail("expected admission")
    }
    let handler = ScriptedHandshakeHandler()
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerHandshakeGateHandler(
        connectionID: UUID(),
        source: source,
        admission: controller,
        ticket: ticket,
        handshake: handler,
        authenticationDeadline: .seconds(20),
        logger: DiscardingListenerLogger()
      ))

    var buffer = channel.allocator.buffer(capacity: 64)
    buffer.writeBytes(try HandshakeFixture.envelope(kind: .pairingRequest))
    try channel.writeInbound(buffer)

    let written = try XCTUnwrap(try channel.readOutbound(as: ByteBuffer.self))
    let envelope = try ListenerHandshakeEnvelope.decode(Data(written.readableBytesView))
    let notice = try JSONDecoder().decode(SecureCloseNotice.self, from: envelope.payload)
    // The per-source counter is shared by every peer behind one address, so
    // the refusal must be indistinguishable from any other pre-auth refusal.
    XCTAssertEqual(notice.reason, ListenerPreAuthAllowlist.collapsedRefusal)
    XCTAssertFalse(channel.isActive)
    XCTAssertTrue(handler.receivedKinds.isEmpty, "a rate-limited attempt never reaches pairing")
  }

  func testARateLimitedRefusalIsByteIdenticalToAMalformedRefusal() throws {
    let ceilings = ListenerCeilings()
    let controller = ListenerAdmissionController(ceilings: ceilings)

    func refusalBytes(source: ListenerSourceKey, payload: Data) throws -> Data {
      guard case .success(let ticket) = controller.admit(source: source) else {
        throw StubPrerequisiteFailure()
      }
      let channel = EmbeddedChannel()
      try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
      try channel.pipeline.syncOperations.addHandler(
        ListenerHandshakeGateHandler(
          connectionID: UUID(),
          source: source,
          admission: controller,
          ticket: ticket,
          handshake: ScriptedHandshakeHandler(),
          authenticationDeadline: .seconds(20),
          logger: DiscardingListenerLogger()
        ))
      var buffer = channel.allocator.buffer(capacity: payload.count)
      buffer.writeBytes(payload)
      try channel.writeInbound(buffer)
      let written = try XCTUnwrap(try channel.readOutbound(as: ByteBuffer.self))
      return Data(written.readableBytesView)
    }

    let rateLimitedSource = ListenerSourceKey(numericAddress: "10.0.0.61")
    for _ in 0..<ceilings.maxPairingAttemptsPerSourcePerMinute {
      XCTAssertTrue(controller.admitHandshakeMessage(.pairingRequest, source: rateLimitedSource))
    }
    let rateLimited = try refusalBytes(
      source: rateLimitedSource,
      payload: try HandshakeFixture.envelope(kind: .pairingRequest)
    )
    let malformed = try refusalBytes(
      source: ListenerSourceKey(numericAddress: "10.0.0.62"),
      payload: Data(#"{"kind":"applicationCommand","payload":"AAAA"}"#.utf8)
    )
    XCTAssertEqual(rateLimited, malformed)
  }

  func testBothPairingMessagesAndBothAuthenticationMessagesAreCharged() throws {
    let ceilings = ListenerCeilings()
    XCTAssertEqual(ListenerHandshakeKind.pairingRequest.sourceWindow, .pairing)
    XCTAssertEqual(ListenerHandshakeKind.pairingConfirmation.sourceWindow, .pairing)
    XCTAssertEqual(ListenerHandshakeKind.sessionAuthRequest.sourceWindow, .authentication)
    XCTAssertEqual(ListenerHandshakeKind.sessionAuthConfirmation.sourceWindow, .authentication)
    for kind in ListenerHandshakeKind.allCases where !kind.isDeviceOriginated {
      XCTAssertNil(kind.sourceWindow, "\(kind) is host-originated and is never charged")
    }

    let pairing = ListenerAdmissionController(ceilings: ceilings)
    let pairingSource = ListenerSourceKey(numericAddress: "10.0.0.7")
    // A confirmation now consumes the same budget as a request.
    XCTAssertTrue(pairing.admitHandshakeMessage(.pairingRequest, source: pairingSource))
    XCTAssertTrue(pairing.admitHandshakeMessage(.pairingConfirmation, source: pairingSource))
    XCTAssertTrue(pairing.admitHandshakeMessage(.pairingRequest, source: pairingSource))
    XCTAssertFalse(pairing.admitHandshakeMessage(.pairingConfirmation, source: pairingSource))

    let auth = ListenerAdmissionController(ceilings: ceilings)
    let authSource = ListenerSourceKey(numericAddress: "10.0.0.8")
    for _ in 0..<ceilings.maxNewConnectionsPerSourcePerMinute {
      XCTAssertTrue(auth.admitHandshakeMessage(.sessionAuthRequest, source: authSource))
    }
    XCTAssertFalse(auth.admitHandshakeMessage(.sessionAuthConfirmation, source: authSource))
    // The two windows are independent.
    XCTAssertTrue(auth.admitHandshakeMessage(.pairingRequest, source: authSource))
  }

  func testDenyingHandlerIsTheFailClosedDefault() async throws {
    let handler = DenyingListenerHandshakeHandler()
    for kind in ListenerPreAuthAllowlist.allowedInboundKinds {
      let envelope = try ListenerHandshakeEnvelope(
        kind: kind,
        payload: Data(repeating: 0x01, count: 8)
      )
      let outcome = await handler.handle(envelope, connectionID: UUID())
      guard case .close(let reason) = outcome else {
        return XCTFail("the default handler must refuse \(kind)")
      }
      XCTAssertEqual(reason, .authenticationFailed)
    }
  }

  func testDefaultConfigurationUsesTheDenyingHandlerAndIsDisabled() throws {
    let configuration = ListenerConfiguration.disabled(
      binding: try ListenerInterfaceBinding.testOnlyLoopback())
    XCTAssertFalse(configuration.isEnabled)
    XCTAssertTrue(configuration.handshake is DenyingListenerHandshakeHandler)
    XCTAssertFalse(configuration.interfacePolicy.allowLoopbackForTests)
  }

  func testGateForwardsNothingInwardBeforeAuthentication() throws {
    let controller = ListenerAdmissionController(ceilings: ListenerCeilings())
    let source = ListenerSourceKey(numericAddress: "10.0.0.8")
    guard case .success(let ticket) = controller.admit(source: source) else {
      return XCTFail("expected admission")
    }
    let channel = EmbeddedChannel()
    try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
    try channel.pipeline.syncOperations.addHandler(
      ListenerHandshakeGateHandler(
        connectionID: UUID(),
        source: source,
        admission: controller,
        ticket: ticket,
        handshake: ScriptedHandshakeHandler(),
        authenticationDeadline: .seconds(20),
        logger: DiscardingListenerLogger()
      ))
    var buffer = channel.allocator.buffer(capacity: 64)
    buffer.writeBytes(try HandshakeFixture.envelope(kind: .sessionAuthRequest))
    try channel.writeInbound(buffer)
    XCTAssertNil(try channel.readInbound(as: ByteBuffer.self))
  }
}
