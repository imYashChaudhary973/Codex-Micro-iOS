import Foundation
import Testing

@testable import Phase2Transport

@Suite(.serialized)
struct NetworkRuntimeTests {
  @Test
  func loopbackNIOTSTLSWebSocketUsesSPKIPinAndTearsDown() async throws {
    let identity = try TestOnlyEphemeralIdentityFactory.make()
    let now = Date()
    let certificate = try ContentNeutralCertificateFactory.makeSelfSigned(
      identity: identity,
      notValidBefore: now.addingTimeInterval(-60),
      notValidAfter: now.addingTimeInterval(3_600)
    )
    let binding = try InterfaceBinding.testOnlyLoopback()
    let policy = InterfacePolicy(allowLoopbackForTests: true)
    let server = NIOTSTLSWebSocketServer(connectionLimit: 2)
    let endpoint = try await server.start(
      binding: binding,
      policy: policy,
      certificate: certificate
    )

    do {
      let url = try #require(
        URL(string: "wss://127.0.0.1:\(endpoint.port)\(HardenedWebSocketPolicy.path)"))
      let message = Data([0x01, 0x02, 0x03, 0x04])
      let response = try await PinnedWebSocketClient(
        expectedSPKISHA256: endpoint.spkiSHA256
      ).exchange(url: url, message: message)
      #expect(response == message)

      let invalidURL = try #require(
        URL(
          string:
            "wss://127.0.0.1:\(endpoint.port)\(HardenedWebSocketPolicy.path)?sentinel=1"
        )
      )
      await #expect(throws: (any Error).self) {
        _ = try await PinnedWebSocketClient(expectedSPKISHA256: endpoint.spkiSHA256)
          .exchange(url: invalidURL, message: message)
      }
      #expect(await server.lastUpgradeRejection() == .pathOrQuery)

      var wrongPin = endpoint.spkiSHA256
      wrongPin[0] ^= 0x01
      do {
        _ = try await PinnedWebSocketClient(expectedSPKISHA256: wrongPin)
          .exchange(url: url, message: message)
        Issue.record("wrong pin unexpectedly connected")
      } catch let error as PinnedWebSocketClientError {
        #expect(error == .pinMismatch)
      }

      try await server.stop()
      let snapshot = await server.snapshot()
      #expect(snapshot.phase == .terminated)
      #expect(snapshot.activeChildren == 0)
      #expect(!snapshot.bonjourPublished)
      #expect(snapshot.groupShutdown)
      try await server.stop()
      await #expect(throws: NetworkTransportError.terminated) {
        _ = try await server.start(binding: binding, policy: policy, certificate: certificate)
      }
    } catch {
      try? await server.stop()
      throw error
    }
  }

  @Test
  func concurrentStartAndStopAlwaysTerminatesOneShotServer() async throws {
    let identity = try TestOnlyEphemeralIdentityFactory.make()
    let now = Date()
    let certificate = try ContentNeutralCertificateFactory.makeSelfSigned(
      identity: identity,
      notValidBefore: now.addingTimeInterval(-60),
      notValidAfter: now.addingTimeInterval(3_600)
    )
    let binding = try InterfaceBinding.testOnlyLoopback()
    let policy = InterfacePolicy(allowLoopbackForTests: true)
    let server = NIOTSTLSWebSocketServer()
    let startTask = Task {
      try? await server.start(binding: binding, policy: policy, certificate: certificate)
    }
    let stopTask = Task {
      try? await server.stop()
    }
    _ = await startTask.value
    _ = await stopTask.value
    try? await server.stop()
    let snapshot = await server.snapshot()
    #expect(snapshot.phase == .terminated)
    #expect(snapshot.activeChildren == 0)
    #expect(snapshot.groupShutdown)
  }

  @Test
  func concurrentStartsAdmitAtMostOneListenerAndDuplicateStopsJoinCleanup() async throws {
    let identity = try TestOnlyEphemeralIdentityFactory.make()
    let now = Date()
    let certificate = try ContentNeutralCertificateFactory.makeSelfSigned(
      identity: identity,
      notValidBefore: now.addingTimeInterval(-60),
      notValidAfter: now.addingTimeInterval(3_600)
    )
    let binding = try InterfaceBinding.testOnlyLoopback()
    let policy = InterfacePolicy(allowLoopbackForTests: true)
    let server = NIOTSTLSWebSocketServer()
    let first = Task {
      try? await server.start(binding: binding, policy: policy, certificate: certificate)
    }
    let second = Task {
      try? await server.start(binding: binding, policy: policy, certificate: certificate)
    }
    let endpoints = await [first.value, second.value].compactMap { $0 }
    #expect(endpoints.count <= 1)
    async let stopOne: Void? = try? server.stop()
    async let stopTwo: Void? = try? server.stop()
    _ = await (stopOne, stopTwo)
    let snapshot = await server.snapshot()
    #expect(snapshot.phase == .terminated)
    #expect(snapshot.activeChildren == 0)
    #expect(snapshot.groupShutdown)
  }

  @Test
  func startRevalidatesBindingAndTerminatesOnFailure() async throws {
    let identity = try TestOnlyEphemeralIdentityFactory.make()
    let now = Date()
    let certificate = try ContentNeutralCertificateFactory.makeSelfSigned(
      identity: identity,
      notValidBefore: now.addingTimeInterval(-60),
      notValidAfter: now.addingTimeInterval(3_600)
    )
    let server = NIOTSTLSWebSocketServer()
    await #expect(throws: NetworkTransportError.invalidBinding) {
      _ = try await server.start(
        binding: InterfaceBinding.testOnlyLoopback(),
        policy: InterfacePolicy(),
        certificate: certificate
      )
    }
    let snapshot = await server.snapshot()
    #expect(snapshot.phase == .terminated)
    #expect(snapshot.activeChildren == 0)
    #expect(snapshot.groupShutdown)
    try await server.stop()
  }
}
