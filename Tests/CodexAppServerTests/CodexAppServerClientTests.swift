import CodexAppServer
import XCTest

final class CodexAppServerClientTests: XCTestCase {
  func testInitializeHandshakeAndRequestCorrelation() async throws {
    let transport = MockJSONLineTransport { message in
      guard let id = message["id"].integer else { return nil }

      switch message["method"].string {
      case "initialize":
        return .object([
          "id": .integer(id),
          "result": .object([
            "codexHome": .string("/tmp/codex"),
            "platformFamily": .string("unix"),
            "platformOs": .string("macos"),
            "userAgent": .string("codex-test"),
          ]),
        ])
      case "account/read":
        return .object([
          "id": .integer(id),
          "result": .object([
            "account": .object([
              "type": .string("chatgpt"),
              "planType": .string("plus"),
            ]),
            "requiresOpenaiAuth": .bool(true),
          ]),
        ])
      default:
        return nil
      }
    }
    let client = CodexAppServerClient(transport: transport)

    let initialized = try await client.start()
    let account = try await client.request(
      method: "account/read",
      params: .object(["refreshToken": .bool(false)])
    )
    await client.stop()

    XCTAssertEqual(initialized["platformOs"].string, "macos")
    XCTAssertEqual(account["account"]["type"].string, "chatgpt")
    XCTAssertEqual(
      transport.messages().compactMap { $0["method"].string },
      ["initialize", "initialized", "account/read"]
    )
  }

  func testRPCErrorIsReturnedToCaller() async throws {
    let transport = MockJSONLineTransport { message in
      guard let id = message["id"].integer else { return nil }
      if message["method"].string == "initialize" {
        return .object([
          "id": .integer(id),
          "result": .object([
            "codexHome": .string("/tmp/codex"),
            "platformFamily": .string("unix"),
            "platformOs": .string("macos"),
            "userAgent": .string("codex-test"),
          ]),
        ])
      }
      return .object([
        "id": .integer(id),
        "error": .object([
          "code": .integer(-32601),
          "message": .string("Method not found"),
        ]),
      ])
    }
    let client = CodexAppServerClient(transport: transport)
    _ = try await client.start()

    do {
      _ = try await client.request(method: "missing/method")
      XCTFail("Expected the request to fail.")
    } catch let error as CodexRPCError {
      XCTAssertEqual(error.code, -32601)
      XCTAssertEqual(error.message, "Method not found")
    }
    await client.stop()
  }

  func testStoredThreadCanBeResumedWithoutStartingTurn() async throws {
    let transport = MockJSONLineTransport { message in
      guard let id = message["id"].integer else { return nil }

      switch message["method"].string {
      case "initialize":
        return .object([
          "id": .integer(id),
          "result": .object([
            "codexHome": .string("/tmp/codex"),
            "platformFamily": .string("unix"),
            "platformOs": .string("macos"),
            "userAgent": .string("codex-test"),
          ]),
        ])
      case "thread/resume":
        return .object([
          "id": .integer(id),
          "result": .object([
            "thread": .object([
              "id": message["params"]["threadId"],
              "updatedAt": .integer(1_754_000_000),
            ])
          ]),
        ])
      default:
        return nil
      }
    }
    let client = CodexAppServerClient(transport: transport)
    _ = try await client.start()

    let response = try await client.request(
      method: "thread/resume",
      params: .object(["threadId": .string("thread-1")])
    )
    await client.stop()

    XCTAssertEqual(response["thread"]["id"].string, "thread-1")
    XCTAssertFalse(
      transport.messages().contains { $0["method"].string == "turn/start" }
    )
  }

  func testServerApprovalRequestIsSurfacedWithoutResolution() async throws {
    let transport = MockJSONLineTransport { message in
      guard
        message["method"].string == "initialize",
        let id = message["id"].integer
      else { return nil }

      return .object([
        "id": .integer(id),
        "result": .object([
          "codexHome": .string("/tmp/codex"),
          "platformFamily": .string("unix"),
          "platformOs": .string("macos"),
          "userAgent": .string("codex-test"),
        ]),
      ])
    }
    let client = CodexAppServerClient(transport: transport)
    _ = try await client.start()
    var events = client.events.makeAsyncIterator()

    try transport.yield(
      .object([
        "id": .integer(42),
        "method": .string("item/commandExecution/requestApproval"),
        "params": .object([
          "threadId": .string("thread-1"),
          "turnId": .string("turn-1"),
          "itemId": .string("item-1"),
        ]),
      ]))

    let event = await events.next()
    await client.stop()

    XCTAssertEqual(
      event,
      .serverRequest(
        id: 42,
        method: "item/commandExecution/requestApproval",
        params: .object([
          "threadId": .string("thread-1"),
          "turnId": .string("turn-1"),
          "itemId": .string("item-1"),
        ])
      )
    )
    XCTAssertFalse(
      transport.messages().contains { $0["id"].integer == 42 },
      "The client must not answer approvals without an explicit user decision."
    )
  }

  func testServerRequestCanBeExplicitlyCancelled() async throws {
    let transport = MockJSONLineTransport { message in
      guard
        message["method"].string == "initialize",
        let id = message["id"].integer
      else { return nil }

      return .object([
        "id": .integer(id),
        "result": .object([
          "codexHome": .string("/tmp/codex"),
          "platformFamily": .string("unix"),
          "platformOs": .string("macos"),
          "userAgent": .string("codex-test"),
        ]),
      ])
    }
    let client = CodexAppServerClient(transport: transport)
    _ = try await client.start()

    try await client.respondToServerRequest(
      id: 42,
      result: .object(["decision": .string("cancel")])
    )
    await client.stop()

    XCTAssertTrue(
      transport.messages().contains {
        $0["id"].integer == 42 && $0["result"]["decision"].string == "cancel"
      }
    )
  }

  func testJSONValuePreservesIntegerIDs() throws {
    let original = JSONValue.object([
      "id": .integer(9_007_199_254_740_991),
      "enabled": .bool(true),
      "items": .array([.string("one"), .null]),
    ])

    let data = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(JSONValue.self, from: data)

    XCTAssertEqual(decoded, original)
    XCTAssertEqual(decoded["id"].integer, 9_007_199_254_740_991)
  }

  func testTurnEventRecorderCapturesSanitizedCompletionSummary() async throws {
    let pair = AsyncStream<AppServerEvent>.makeStream()
    pair.continuation.yield(
      .notification(
        method: "turn/started",
        params: .object(["turn": .object(["id": .string("turn-1")])])
      )
    )
    pair.continuation.yield(
      .notification(
        method: "item/agentMessage/delta",
        params: .object([
          "turnId": .string("turn-1"),
          "delta": .string("private response"),
        ])
      )
    )
    pair.continuation.yield(
      .notification(
        method: "turn/completed",
        params: .object([
          "turn": .object([
            "id": .string("turn-1"),
            "status": .string("completed"),
          ])
        ])
      )
    )
    pair.continuation.finish()

    let summary = try await TurnEventRecorder.collect(
      events: pair.stream,
      turnID: "turn-1",
      timeout: .seconds(1)
    )

    XCTAssertEqual(summary.finalStatus, "completed")
    XCTAssertEqual(summary.agentMessageCharacterCount, 16)
    XCTAssertTrue(summary.serverRequestCounts.isEmpty)
    XCTAssertEqual(summary.notificationCounts["turn/started"], 1)
    XCTAssertEqual(summary.notificationCounts["item/agentMessage/delta"], 1)
    XCTAssertEqual(summary.notificationCounts["turn/completed"], 1)
  }

  func testTurnEventRecorderFailsClosedOnServerRequest() async throws {
    let pair = AsyncStream<AppServerEvent>.makeStream()
    pair.continuation.yield(
      .serverRequest(
        id: 42,
        method: "item/commandExecution/requestApproval",
        params: .object([
          "threadId": .string("thread-1"),
          "turnId": .string("turn-1"),
        ])
      )
    )
    pair.continuation.finish()

    do {
      _ = try await TurnEventRecorder.collect(
        events: pair.stream,
        turnID: "turn-1",
        timeout: .seconds(1)
      )
      XCTFail("Expected the recorder to reject a server request.")
    } catch let error as TurnEventRecorderError {
      XCTAssertEqual(
        error,
        .unexpectedServerRequest(
          id: 42,
          method: "item/commandExecution/requestApproval"
        )
      )
    }
  }

  func testTurnEventRecorderTimesOut() async throws {
    let pair = AsyncStream<AppServerEvent>.makeStream()

    do {
      _ = try await TurnEventRecorder.collect(
        events: pair.stream,
        turnID: "turn-1",
        timeout: .milliseconds(10)
      )
      XCTFail("Expected the recorder to time out.")
    } catch let error as TurnEventRecorderError {
      XCTAssertEqual(error, .timedOut(turnID: "turn-1"))
    }
    pair.continuation.finish()
  }

  func testWaitUntilStartedMatchesOnlyRequestedTurn() async throws {
    let pair = AsyncStream<AppServerEvent>.makeStream()
    pair.continuation.yield(
      .notification(
        method: "turn/started",
        params: .object(["turn": .object(["id": .string("turn-other")])])
      )
    )
    pair.continuation.yield(
      .notification(
        method: "turn/started",
        params: .object(["turn": .object(["id": .string("turn-1")])])
      )
    )
    pair.continuation.finish()

    try await TurnEventRecorder.waitUntilStarted(
      events: pair.stream,
      turnID: "turn-1",
      timeout: .seconds(1)
    )
  }

  func testThreadSnapshotRebuildsAndAppliesDuplicateLifecycleEvents() throws {
    var snapshot = try ThreadRuntimeSnapshot(
      thread: .object([
        "id": .string("thread-1"),
        "status": .object([
          "type": .string("active"),
          "activeFlags": .array([]),
        ]),
        "turns": .array([
          .object([
            "id": .string("turn-1"),
            "status": .string("completed"),
          ]),
          .object([
            "id": .string("turn-2"),
            "status": .string("inProgress"),
          ]),
        ]),
      ])
    )

    XCTAssertEqual(snapshot.status, "active")
    XCTAssertEqual(snapshot.activeTurnID, "turn-2")
    XCTAssertEqual(snapshot.lastTurnStatus, "inProgress")

    let completed = AppServerEvent.notification(
      method: "turn/completed",
      params: .object([
        "turn": .object([
          "id": .string("turn-2"),
          "status": .string("interrupted"),
        ])
      ])
    )
    snapshot.apply(completed, routedTo: "thread-1")
    snapshot.apply(completed, routedTo: "thread-1")

    XCTAssertNil(snapshot.activeTurnID)
    XCTAssertEqual(snapshot.lastTurnID, "turn-2")
    XCTAssertEqual(snapshot.lastTurnStatus, "interrupted")
  }

  func testThreadSnapshotIgnoresEventsRoutedToAnotherThread() throws {
    var snapshot = try ThreadRuntimeSnapshot(
      thread: .object([
        "id": .string("thread-1"),
        "status": .object(["type": .string("idle")]),
        "turns": .array([]),
      ])
    )
    snapshot.apply(
      .notification(
        method: "turn/started",
        params: .object([
          "turn": .object([
            "id": .string("turn-other"),
            "status": .string("inProgress"),
          ])
        ])
      ),
      routedTo: "thread-2"
    )

    XCTAssertNil(snapshot.activeTurnID)
    XCTAssertNil(snapshot.lastTurnID)
  }

  func testFreshClientRebuildsEquivalentThreadSnapshotAfterRestart() async throws {
    let responder: @Sendable (JSONValue) -> JSONValue? = { message in
      guard let id = message["id"].integer else { return nil }

      switch message["method"].string {
      case "initialize":
        return .object([
          "id": .integer(id),
          "result": .object([
            "codexHome": .string("/tmp/codex"),
            "platformFamily": .string("unix"),
            "platformOs": .string("macos"),
            "userAgent": .string("codex-test"),
          ]),
        ])
      case "thread/read":
        return .object([
          "id": .integer(id),
          "result": .object([
            "thread": .object([
              "id": message["params"]["threadId"],
              "status": .object([
                "type": .string("active"),
                "activeFlags": .array([]),
              ]),
              "turns": .array([
                .object([
                  "id": .string("turn-1"),
                  "status": .string("inProgress"),
                ])
              ]),
            ])
          ]),
        ])
      default:
        return nil
      }
    }

    let firstTransport = MockJSONLineTransport(responder: responder)
    let firstClient = CodexAppServerClient(transport: firstTransport)
    _ = try await firstClient.start()
    let beforeRestart = try await firstClient.readThreadSnapshot(threadID: "thread-1")
    await firstClient.stop()

    let secondTransport = MockJSONLineTransport(responder: responder)
    let secondClient = CodexAppServerClient(transport: secondTransport)
    _ = try await secondClient.start()
    let afterRestart = try await secondClient.readThreadSnapshot(threadID: "thread-1")
    await secondClient.stop()

    XCTAssertEqual(afterRestart, beforeRestart)
    XCTAssertEqual(afterRestart.activeTurnID, "turn-1")
    XCTAssertFalse(
      secondTransport.messages().contains { $0["method"].string == "turn/start" }
    )
  }

  func testTurnEventRecorderKeepsPlanDiffAndFailureContentSanitized() async throws {
    let pair = AsyncStream<AppServerEvent>.makeStream()
    pair.continuation.yield(
      .notification(
        method: "turn/plan/updated",
        params: .object([
          "turnId": .string("turn-1"),
          "explanation": .string("sensitive plan"),
        ])
      )
    )
    pair.continuation.yield(
      .notification(
        method: "turn/diff/updated",
        params: .object([
          "turnId": .string("turn-1"),
          "diff": .string("sensitive diff"),
        ])
      )
    )
    pair.continuation.yield(
      .notification(
        method: "item/started",
        params: .object([
          "turnId": .string("turn-1"),
          "item": .object([
            "id": .string("item-1"),
            "type": .string("commandExecution"),
            "command": .string("sensitive command"),
          ]),
        ])
      )
    )
    pair.continuation.yield(
      .notification(
        method: "item/completed",
        params: .object([
          "turnId": .string("turn-1"),
          "item": .object([
            "id": .string("item-1"),
            "type": .string("commandExecution"),
          ]),
        ])
      )
    )
    pair.continuation.yield(
      .notification(
        method: "turn/completed",
        params: .object([
          "turn": .object([
            "id": .string("turn-1"),
            "status": .string("failed"),
            "error": .object(["message": .string("sensitive failure")]),
          ])
        ])
      )
    )
    pair.continuation.finish()

    let summary = try await TurnEventRecorder.collect(
      events: pair.stream,
      turnID: "turn-1",
      timeout: .seconds(1)
    )

    XCTAssertEqual(summary.finalStatus, "failed")
    XCTAssertEqual(summary.notificationCounts["turn/plan/updated"], 1)
    XCTAssertEqual(summary.notificationCounts["turn/diff/updated"], 1)
    XCTAssertEqual(summary.notificationCounts["item/started"], 1)
    XCTAssertEqual(summary.notificationCounts["item/completed"], 1)
  }
}
