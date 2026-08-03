import CodexAppServer
import CodexTestSupport
import Foundation
import XCTest

@testable import MacBridgeCore

/// The exact JSON `LiveCodexRuntimeSession` puts on the wire.
///
/// Every other steer and turn-start test in this repository drives the
/// `CodexTurnSteering` / `CodexTurnStarting` *seam* with a double, which
/// proves the gateway's authorization logic and nothing about the request.
/// That gap is not hypothetical: Step 2.11 wrote `turn/steer` from the
/// documented architecture with a `turnId` field, every seam test passed, and
/// the Step 2.14 live probe found Codex 0.146.0 rejecting it outright with
/// `missing field expectedTurnId`. Every steer would have failed.
///
/// These tests assert the field names against a fake transport, so the same
/// class of defect fails here rather than on a phone.
final class RuntimeWireShapeTests: XCTestCase {

  /// `turn/steer` takes `expectedTurnId`, not `turnId`.
  ///
  /// The name carries meaning: it makes the call a compare-and-swap, so Codex
  /// refuses the steer unless that turn is still the thread's current one.
  /// Sending `turnId` is not a near-miss that degrades — it is a hard
  /// rejection.
  func testSteerTurnSendsExpectedTurnIdNotTurnId() async throws {
    let server = FakeCodexAppServer()
    server.stubResult("turn/steer", .object([:]))
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let session = LiveCodexRuntimeSession(client: client)

    try await session.steerTurn(threadID: "thread-1", turnID: "turn-1", prompt: "go left")

    let request = try XCTUnwrap(server.requests("turn/steer").first)
    XCTAssertEqual(request["params"]["threadId"].string, "thread-1")
    XCTAssertEqual(
      request["params"]["expectedTurnId"].string, "turn-1",
      "Codex rejects turn/steer without expectedTurnId")
    XCTAssertNil(
      request["params"]["turnId"].string,
      "turnId is the interrupt field; steer does not accept it")
    await client.stop()
  }

  /// Steering carries no sandbox, approval, root, or network field, so a
  /// steered turn keeps the policy it was started under and steering can
  /// never widen it.
  func testSteerTurnCarriesNoPolicyFields() async throws {
    let server = FakeCodexAppServer()
    server.stubResult("turn/steer", .object([:]))
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let session = LiveCodexRuntimeSession(client: client)

    try await session.steerTurn(threadID: "thread-1", turnID: "turn-1", prompt: "go left")

    let params = try XCTUnwrap(server.requests("turn/steer").first)["params"]
    for forbidden in ["sandboxPolicy", "approvalPolicy", "writableRoots", "cwd"] {
      XCTAssertEqual(params[forbidden], .null, "steer widened the turn via \(forbidden)")
    }
    let input = try XCTUnwrap(params["input"].array?.first)
    XCTAssertEqual(input["type"].string, "text")
    XCTAssertEqual(input["text"].string, "go left")
    await client.stop()
  }

  /// The `workspaceWrite` form of `turn/start` names its roots under
  /// `writableRoots` inside `sandboxPolicy`, and the type is the camel-cased
  /// `workspaceWrite` — the *thread*-level vocabulary is kebab-cased
  /// (`workspace-write`), and the two levels are not interchangeable.
  func testWorkspaceWriteTurnStartCarriesItsRoots() async throws {
    let server = FakeCodexAppServer()
    server.stubResult("turn/start", .object(["turn": .object(["id": .string("turn-9")])]))
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let session = LiveCodexRuntimeSession(client: client)
    let policy = PhoneTurnPolicy.resolve(
      effectiveProfile: .runWorkspace, writableRoots: ["/tmp/project-a"])

    let turnID = try await session.startTurn(
      threadID: "thread-1", prompt: "do it", policy: policy)

    XCTAssertEqual(turnID, "turn-9")
    let params = try XCTUnwrap(server.requests("turn/start").first)["params"]
    XCTAssertEqual(params["sandboxPolicy"]["type"].string, "workspaceWrite")
    XCTAssertEqual(params["sandboxPolicy"]["networkAccess"].bool, false)
    XCTAssertEqual(
      params["sandboxPolicy"]["writableRoots"].array?.first?.string, "/tmp/project-a")
    XCTAssertEqual(params["approvalPolicy"].string, "untrusted")
    await client.stop()
  }

  /// A read-only turn names no roots at all, rather than naming an empty
  /// list. An empty `writableRoots` key would be a policy statement the
  /// read-only form has no business making.
  func testReadOnlyTurnStartOmitsWritableRootsEntirely() async throws {
    let server = FakeCodexAppServer()
    server.stubResult("turn/start", .object(["turn": .object(["id": .string("turn-9")])]))
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let session = LiveCodexRuntimeSession(client: client)
    let policy = PhoneTurnPolicy.resolve(effectiveProfile: .runReadOnly, writableRoots: [])

    _ = try await session.startTurn(threadID: "thread-1", prompt: "look", policy: policy)

    let params = try XCTUnwrap(server.requests("turn/start").first)["params"]
    XCTAssertEqual(params["sandboxPolicy"]["type"].string, "readOnly")
    XCTAssertEqual(params["sandboxPolicy"]["writableRoots"], .null)
    await client.stop()
  }

  /// `turn/interrupt` keeps `turnId`. The two methods genuinely differ, and
  /// fixing steer must not "tidy" interrupt into the same shape — interrupt
  /// is proven against a live Codex by the merged Phase 0 spike.
  func testInterruptStillSendsTurnId() async throws {
    let server = FakeCodexAppServer()
    server.stubResult("turn/interrupt", .object([:]))
    let client = CodexAppServerClient(transport: server, timeout: .seconds(2))
    _ = try await client.start()
    let session = LiveCodexRuntimeSession(client: client)

    try await session.interruptTurn(threadID: "thread-1", turnID: "turn-1")

    let params = try XCTUnwrap(server.requests("turn/interrupt").first)["params"]
    XCTAssertEqual(params["turnId"].string, "turn-1")
    XCTAssertEqual(params["expectedTurnId"], .null)
    await client.stop()
  }
}
