import CodexAppServer
import CodexTestSupport
import XCTest

/// Client-level protocol-edge contracts verified against the scripted fake
/// app-server: malformed traffic surfaces as warnings, unstubbed methods fail
/// closed, silence times out, and only explicit responses reach the server.
final class FakeAppServerClientContractTests: XCTestCase {
  func testMalformedAndMethodlessServerTrafficSurfacesAsProtocolWarnings() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    var events = client.events.makeAsyncIterator()

    server.emitRaw(CodexAppServerFixtures.malformedLine)
    try server.emit(CodexAppServerFixtures.messageWithoutMethod())
    try server.emit(CodexAppServerFixtures.responseWithUnknownRPCID(999))

    for _ in 0..<3 {
      let event = try await nextEvent(&events)
      guard case .protocolWarning = event else {
        XCTFail("Expected a protocol warning, received \(event).")
        return
      }
    }
    await client.stop()
  }

  func testUnstubbedRequestMethodFailsClosedWithMethodNotFound() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()

    do {
      _ = try await client.request(method: "model/list")
      XCTFail("Expected the unstubbed method to fail.")
    } catch let error as CodexRPCError {
      XCTAssertEqual(error.code, -32601)
    }
    await client.stop()
  }

  func testSilentMethodExercisesTheRequestTimeoutPath() async throws {
    let server = FakeCodexAppServer()
    server.stub("thread/list") { _, _ in .silence }
    let client = CodexAppServerClient(transport: server, timeout: .milliseconds(50))
    _ = try await client.start()

    do {
      _ = try await client.request(method: "thread/list")
      XCTFail("Expected the silent method to time out.")
    } catch let error as CodexAppServerError {
      XCTAssertEqual(error, .requestTimedOut(method: "thread/list"))
    }
    await client.stop()
  }

  func testScriptedServerRequestIsSurfacedAndOnlyExplicitResponsesAreSent() async throws {
    let server = FakeCodexAppServer()
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    var events = client.events.makeAsyncIterator()

    try server.emit(
      CodexAppServerFixtures.commandApprovalRequest(
        rpcID: 55,
        threadID: "thread-1",
        turnID: "turn-1",
        startedAt: Date()
      ))
    let event = try await nextEvent(&events)
    guard case .serverRequest(let id, let method, _) = event else {
      XCTFail("Expected a server request, received \(event).")
      return
    }
    XCTAssertEqual(id, 55)
    XCTAssertEqual(method, "item/commandExecution/requestApproval")
    XCTAssertTrue(
      server.serverRequestResponses().isEmpty,
      "Surfacing a server request must not answer it."
    )

    try await client.respondToServerRequest(
      id: 55,
      result: .object(["decision": .string("cancel")])
    )
    await client.stop()

    let response = try XCTUnwrap(server.serverRequestResponse(rpcID: 55))
    XCTAssertEqual(response["result"]["decision"].string, "cancel")
    XCTAssertEqual(server.serverRequestResponses().count, 1)
  }
}

private func nextEvent(
  _ events: inout AsyncStream<AppServerEvent>.AsyncIterator
) async throws -> AppServerEvent {
  let event = await events.next()
  return try XCTUnwrap(event)
}
