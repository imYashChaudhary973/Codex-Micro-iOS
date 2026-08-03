import CodexAppServer
import Foundation
import MacBridgeCore

@main
struct CodexMicroSpike {
  static func main() async {
    do {
      let arguments = Array(CommandLine.arguments.dropFirst())
      let command = arguments.first ?? "doctor"

      if ["help", "--help", "-h"].contains(command) {
        printUsage()
        return
      }
      guard
        [
          "compatibility", "doctor", "threads", "resume-recent", "restart-probe", "smoke-turn",
          "steer-probe",
        ].contains(
          command
        )
      else {
        throw SpikeError.unknownCommand(command)
      }

      if command == "compatibility" {
        let executableURL = try CodexExecutableLocator.locate()
        let report = try await SystemCodexCompatibilityProbe(
          codexExecutableURL: executableURL
        ).probe()
        let decision = CodexCompatibilityPolicy.phase1.evaluate(report)
        print("Codex Micro Phase 1 compatibility probe")
        print("  Codex version: \(report.codexVersion)")
        print("  canonical schema digest: \(report.schemaDigest)")
        print("  Phase 1 policy: \(decision == .supported ? "supported" : "blocked")")
        return
      }

      let client = CodexAppServerClient(timeout: .seconds(30))

      do {
        let initialize = try await client.start()

        switch command {
        case "doctor":
          try await runDoctor(client: client, initialize: initialize)
        case "threads":
          try await listThreads(client: client, arguments: Array(arguments.dropFirst()))
        case "resume-recent":
          try await resumeRecentThread(
            client: client,
            arguments: Array(arguments.dropFirst())
          )
        case "restart-probe":
          try await runRestartProbe(
            firstClient: client,
            arguments: Array(arguments.dropFirst())
          )
        case "smoke-turn":
          try await runSmokeTurn(client: client, arguments: Array(arguments.dropFirst()))
        case "steer-probe":
          try await runSteerProbe(client: client, arguments: Array(arguments.dropFirst()))
        default:
          preconditionFailure("Command was validated before app-server startup.")
        }
        await client.stop()
      } catch {
        await client.stop()
        throw error
      }
    } catch {
      FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
      Foundation.exit(EXIT_FAILURE)
    }
  }

  private static func runDoctor(
    client: CodexAppServerClient,
    initialize: JSONValue
  ) async throws {
    let account = try await client.request(
      method: "account/read",
      params: .object(["refreshToken": .bool(false)])
    )
    let threads = try await client.request(
      method: "thread/list",
      params: .object([
        "limit": .integer(20),
        "sortKey": .string("recency_at"),
        "sortDirection": .string("desc"),
      ])
    )

    let accountValue = account["account"]
    let accountType = accountValue["type"].string ?? "none"
    let plan = accountValue["planType"].string ?? "unavailable"
    let threadValues = threads["data"].array ?? []
    let statuses = counts(for: threadValues, value: threadStatus)
    let sources = counts(for: threadValues, value: threadSource)
    let threadReadVerified = try await verifyThreadRead(
      client: client,
      firstThread: threadValues.first
    )

    print("Codex Micro Phase 0 doctor")
    print("  platform: \(initialize["platformOs"].string ?? "unknown")")
    print("  app-server: \(initialize["userAgent"].string ?? "available")")
    print("  auth: \(accountType)")
    print("  plan: \(plan)")
    print("  recent threads: \(threadValues.count)")
    print("  thread read: \(threadReadVerified ? "verified" : "not available")")
    print("  statuses: \(format(counts: statuses))")
    print("  sources: \(format(counts: sources))")
    print("  result: ready for read-only Phase 0 integration")
  }

  private static func verifyThreadRead(
    client: CodexAppServerClient,
    firstThread: JSONValue?
  ) async throws -> Bool {
    guard let threadID = firstThread?["id"].string else { return false }
    let response = try await client.request(
      method: "thread/read",
      params: .object([
        "threadId": .string(threadID),
        "includeTurns": .bool(false),
      ])
    )
    return response["thread"]["id"].string == threadID
  }

  private static func listThreads(
    client: CodexAppServerClient,
    arguments: [String]
  ) async throws {
    let includePreview = arguments.contains("--include-preview")
    let limit = try parsedLimit(arguments) ?? 6
    let response = try await client.request(
      method: "thread/list",
      params: .object([
        "limit": .integer(Int64(limit)),
        "sortKey": .string("recency_at"),
        "sortDirection": .string("desc"),
      ])
    )
    let threads = response["data"].array ?? []

    if threads.isEmpty {
      print("No Codex threads were returned.")
      return
    }

    for thread in threads {
      let id = thread["id"].string.map { String($0.prefix(8)) } ?? "unknown"
      let project = projectName(from: thread["cwd"].string)
      let status = threadStatus(thread)
      let source = threadSource(thread)
      var line = "\(id)  \(status)  \(source)  \(project)"
      if includePreview {
        let preview = thread["name"].string ?? thread["preview"].string ?? ""
        line += "  \(singleLine(preview, limit: 80))"
      }
      print(line)
    }
  }

  private static func runSmokeTurn(
    client: CodexAppServerClient,
    arguments: [String]
  ) async throws {
    guard arguments.contains("--confirm-live-turn") else {
      throw SpikeError.liveTurnConfirmationRequired
    }

    let interruptImmediately = arguments.contains("--interrupt-immediately")
    let cancelCommandApproval = arguments.contains("--approval-cancel")
    let cancelFileApproval = arguments.contains("--file-approval-cancel")
    let selectedModeCount =
      [interruptImmediately, cancelCommandApproval, cancelFileApproval].filter { $0 }.count
    guard selectedModeCount <= 1 else {
      throw SpikeError.conflictingSmokeTurnModes
    }
    let expectedApprovalMethod: String? =
      if cancelFileApproval {
        "item/fileChange/requestApproval"
      } else if cancelCommandApproval {
        "item/commandExecution/requestApproval"
      } else {
        nil
      }
    var threadID: String?
    var turnID: String?

    do {
      let threadResponse = try await client.request(
        method: "thread/start",
        params: .object([
          "ephemeral": .bool(true),
          "cwd": .string(FileManager.default.currentDirectoryPath),
          "approvalPolicy": .string("untrusted"),
          "sandbox": .string("read-only"),
          "serviceName": .string("codex_micro_phase0"),
        ])
      )
      guard let startedThreadID = threadResponse["thread"]["id"].string else {
        throw SpikeError.missingResponseID("thread/start")
      }
      threadID = startedThreadID

      let prompt =
        if interruptImmediately {
          "Without using tools or reading files, write a detailed 2,000-word explanation of "
            + "why deterministic interruption tests matter in distributed systems."
        } else if cancelCommandApproval {
          "Use the terminal tool to run /usr/bin/python3 with arguments -c and "
            + "print(\"CODEX_MICRO_APPROVAL_PROBE\"), then report whether it succeeded. "
            + "Do not use any other tool."
        } else if cancelFileApproval {
          "Use the file editing tool to append a line containing "
            + "CODEX_MICRO_FILE_APPROVAL_PROBE to README.md. Do not use a terminal command "
            + "and do not modify any other file."
        } else {
          "Without using tools or reading files, reply with exactly "
            + "CODEX_MICRO_PHASE_0_OK."
        }

      let turnResponse = try await client.request(
        method: "turn/start",
        params: .object([
          "threadId": .string(startedThreadID),
          "input": .array([
            .object([
              "type": .string("text"),
              "text": .string(prompt),
            ])
          ]),
          "approvalPolicy": .string("untrusted"),
          "sandboxPolicy": .object([
            "type": .string("readOnly"),
            "networkAccess": .bool(false),
          ]),
          "summary": .string("none"),
        ])
      )
      guard let startedTurnID = turnResponse["turn"]["id"].string else {
        throw SpikeError.missingResponseID("turn/start")
      }
      turnID = startedTurnID

      let interruptOnStart: (@Sendable () async throws -> Void)? =
        if interruptImmediately {
          {
            _ = try await client.request(
              method: "turn/interrupt",
              params: .object([
                "threadId": .string(startedThreadID),
                "turnId": .string(startedTurnID),
              ])
            )
          }
        } else {
          nil
        }

      let serverRequestHandler: TurnEventRecorder.ServerRequestHandler? =
        if let expectedApprovalMethod {
          { id, method, params in
            guard method == expectedApprovalMethod,
              params["turnId"].string == startedTurnID
            else {
              throw TurnEventRecorderError.unexpectedServerRequest(id: id, method: method)
            }
            try await client.respondToServerRequest(
              id: id,
              result: .object(["decision": .string("cancel")])
            )
          }
        } else {
          nil
        }

      let summary = try await TurnEventRecorder.collect(
        events: client.events,
        turnID: startedTurnID,
        onTurnStarted: interruptOnStart,
        onServerRequest: serverRequestHandler
      )
      try await unsubscribe(client: client, threadID: startedThreadID)
      threadID = nil

      if let expectedApprovalMethod {
        guard summary.serverRequestCounts[expectedApprovalMethod, default: 0] > 0 else {
          throw SpikeError.approvalRequestNotObserved(summary.finalStatus)
        }
        print("Codex Micro Phase 0 approval-cancel probe")
        print("  isolation: ephemeral, read-only, network-disabled")
        print("  approval request: \(expectedApprovalMethod)")
        print("  decision: cancel")
        print("  final status: \(summary.finalStatus)")
        print("  result: explicit denial round-trip verified; action did not execute")
        return
      }

      print("Codex Micro Phase 0 live-turn probe")
      print("  mode: \(interruptImmediately ? "immediate-interrupt" : "completion")")
      print("  isolation: ephemeral, read-only, network-disabled")
      print("  approval policy: untrusted; requests are never auto-answered")
      print("  final status: \(summary.finalStatus)")
      print("  agent message characters: \(summary.agentMessageCharacterCount)")
      print("  events: \(format(counts: summary.notificationCounts))")
      print("  result: sanitized event lifecycle captured")
    } catch {
      await cancelTurnAndUnsubscribe(client: client, threadID: threadID, turnID: turnID)
      throw error
    }
  }

  private static func resumeRecentThread(
    client: CodexAppServerClient,
    arguments: [String]
  ) async throws {
    guard arguments == ["--confirm-existing-thread"] else {
      throw SpikeError.existingThreadConfirmationRequired
    }

    let listResponse = try await client.request(
      method: "thread/list",
      params: .object([
        "limit": .integer(20),
        "sortKey": .string("recency_at"),
        "sortDirection": .string("desc"),
      ])
    )
    let listedThreads = listResponse["data"].array ?? []
    guard let listedThread = listedThreads.last,
      let threadID = listedThread["id"].string
    else {
      throw SpikeError.noRecentThread
    }

    let readResponse = try await client.request(
      method: "thread/read",
      params: .object([
        "threadId": .string(threadID),
        "includeTurns": .bool(false),
      ])
    )
    let baselineThread = readResponse["thread"]
    guard baselineThread["id"].string == threadID else {
      throw SpikeError.missingResponseID("thread/read")
    }

    var subscribed = false
    do {
      let resumeResponse = try await client.request(
        method: "thread/resume",
        params: .object(["threadId": .string(threadID)])
      )
      subscribed = true
      let resumedThread = resumeResponse["thread"]
      guard resumedThread["id"].string == threadID else {
        throw SpikeError.missingResponseID("thread/resume")
      }

      let beforeTimestamp = baselineThread["updatedAt"].integer
      let afterTimestamp = resumedThread["updatedAt"].integer
      let timestampUnchanged =
        beforeTimestamp != nil && afterTimestamp != nil && beforeTimestamp == afterTimestamp

      try await unsubscribe(client: client, threadID: threadID)
      subscribed = false

      print("Codex Micro Phase 0 resume probe")
      print("  selected: recent stored thread; content redacted")
      print("  source: \(threadSource(listedThread))")
      print("  project: \(projectName(from: listedThread["cwd"].string))")
      print("  identity: verified")
      print(
        "  timestamp fields: read=\(beforeTimestamp == nil ? "missing" : "present"), "
          + "resume=\(afterTimestamp == nil ? "missing" : "present")"
      )
      print("  timestamp unchanged: \(timestampUnchanged ? "yes" : "not verified")")
      print("  turn started: no")
      print("  result: thread resumed and unsubscribed")
    } catch {
      if subscribed {
        try? await unsubscribe(client: client, threadID: threadID)
      }
      throw error
    }
  }

  private static func runRestartProbe(
    firstClient: CodexAppServerClient,
    arguments: [String]
  ) async throws {
    guard arguments == ["--confirm-persisted-test-thread"] else {
      throw SpikeError.persistedThreadConfirmationRequired
    }

    var threadID: String?
    var firstClientStopped = false
    var replacementStarted = false
    let replacement = CodexAppServerClient(timeout: .seconds(30))

    do {
      let threadResponse = try await firstClient.request(
        method: "thread/start",
        params: .object([
          "ephemeral": .bool(false),
          "cwd": .string(FileManager.default.currentDirectoryPath),
          "approvalPolicy": .string("untrusted"),
          "sandbox": .string("read-only"),
          "serviceName": .string("codex_micro_phase0_restart_probe"),
        ])
      )
      guard let startedThreadID = threadResponse["thread"]["id"].string else {
        throw SpikeError.missingResponseID("thread/start")
      }
      threadID = startedThreadID

      let turnResponse = try await firstClient.request(
        method: "turn/start",
        params: .object([
          "threadId": .string(startedThreadID),
          "input": .array([
            .object([
              "type": .string("text"),
              "text": .string(
                "Without using tools or reading files, write a detailed 2,000-word "
                  + "explanation of restart recovery in event-driven clients."
              ),
            ])
          ]),
          "approvalPolicy": .string("untrusted"),
          "sandboxPolicy": .object([
            "type": .string("readOnly"),
            "networkAccess": .bool(false),
          ]),
          "summary": .string("none"),
        ])
      )
      guard let turnID = turnResponse["turn"]["id"].string else {
        throw SpikeError.missingResponseID("turn/start")
      }

      try await TurnEventRecorder.waitUntilStarted(
        events: firstClient.events,
        turnID: turnID
      )
      await firstClient.stop()
      firstClientStopped = true

      _ = try await replacement.start()
      replacementStarted = true
      let readResponse = try await replacement.request(
        method: "thread/read",
        params: .object([
          "threadId": .string(startedThreadID),
          "includeTurns": .bool(true),
        ])
      )
      let recoveredThread = readResponse["thread"]
      let snapshot = try ThreadRuntimeSnapshot(thread: recoveredThread)
      let turnCount = recoveredThread["turns"].array?.count ?? 0
      guard snapshot.threadID == startedThreadID, turnCount == 1 else {
        throw SpikeError.restartRecoveryMismatch(turnCount: turnCount)
      }

      _ = try await replacement.request(
        method: "thread/archive",
        params: .object(["threadId": .string(startedThreadID)])
      )
      threadID = nil
      await replacement.stop()

      print("Codex Micro Phase 0 restart probe")
      print("  isolation: persisted test thread, read-only, network-disabled")
      print("  first client: stopped after matching turn/started")
      print("  replacement client: initialized and thread/read completed")
      print("  recovered turns: \(turnCount)")
      print("  recovered last status: \(snapshot.lastTurnStatus ?? "unknown")")
      print("  duplicate turn/start sent: no")
      print("  cleanup: test thread archived")
      print("  result: restart state rebuilt without duplicating agent work")
    } catch {
      if let threadID {
        if !firstClientStopped {
          _ = try? await firstClient.request(
            method: "thread/archive",
            params: .object(["threadId": .string(threadID)])
          )
        } else if replacementStarted {
          _ = try? await replacement.request(
            method: "thread/archive",
            params: .object(["threadId": .string(threadID)])
          )
        } else {
          let cleanupClient = CodexAppServerClient(timeout: .seconds(30))
          if (try? await cleanupClient.start()) != nil {
            _ = try? await cleanupClient.request(
              method: "thread/archive",
              params: .object(["threadId": .string(threadID)])
            )
          }
          await cleanupClient.stop()
        }
      }
      if !firstClientStopped {
        await firstClient.stop()
      }
      await replacement.stop()
      throw error
    }
  }

  private static func cancelTurnAndUnsubscribe(
    client: CodexAppServerClient,
    threadID: String?,
    turnID: String?
  ) async {
    if let threadID, let turnID {
      _ = try? await client.request(
        method: "turn/interrupt",
        params: .object([
          "threadId": .string(threadID),
          "turnId": .string(turnID),
        ])
      )
    }
    if let threadID {
      try? await unsubscribe(client: client, threadID: threadID)
    }
  }

  private static func unsubscribe(
    client: CodexAppServerClient,
    threadID: String
  ) async throws {
    _ = try await client.request(
      method: "thread/unsubscribe",
      params: .object(["threadId": .string(threadID)])
    )
  }

  private static func parsedLimit(_ arguments: [String]) throws -> Int? {
    guard let index = arguments.firstIndex(of: "--limit") else { return nil }
    guard arguments.indices.contains(index + 1), let value = Int(arguments[index + 1]),
      1...100 ~= value
    else {
      throw SpikeError.invalidLimit
    }
    return value
  }

  private static func threadStatus(_ thread: JSONValue) -> String {
    let status = thread["status"]
    return status.string
      ?? status["type"].string
      ?? status.object?.keys.sorted().first
      ?? "unknown"
  }

  private static func threadSource(_ thread: JSONValue) -> String {
    let source = thread["source"]
    return source.string
      ?? source["type"].string
      ?? source.object?.keys.sorted().first
      ?? "unknown"
  }

  private static func projectName(from path: String?) -> String {
    guard let path, !path.isEmpty else { return "unknown-project" }
    return URL(fileURLWithPath: path).lastPathComponent
  }

  private static func singleLine(_ value: String, limit: Int) -> String {
    let normalized =
      value
      .replacingOccurrences(of: "\n", with: " ")
      .replacingOccurrences(of: "\r", with: " ")
    guard normalized.count > limit else { return normalized }
    return String(normalized.prefix(limit - 1)) + "…"
  }

  private static func counts(
    for values: [JSONValue],
    value: (JSONValue) -> String
  ) -> [String: Int] {
    values.reduce(into: [:]) { result, item in
      result[value(item), default: 0] += 1
    }
  }

  private static func format(counts: [String: Int]) -> String {
    if counts.isEmpty { return "none" }
    return counts.keys.sorted().map { "\($0)=\(counts[$0] ?? 0)" }.joined(separator: ", ")
  }

  private static func printUsage() {
    print(
      """
      Usage: codex-micro-spike <command>

        doctor                          Verify app-server, auth, and thread discovery
        threads [--limit N]             List redacted recent thread summaries
        threads --include-preview       Include local thread titles/previews
        resume-recent --confirm-existing-thread
                                        Resume, verify, and unsubscribe the latest thread
        restart-probe --confirm-persisted-test-thread
                                        Restart during one disposable read-only turn
        smoke-turn --confirm-live-turn  Run an ephemeral, read-only completion probe
          [--interrupt-immediately]     Interrupt the disposable turn immediately
          [--approval-cancel]           Cancel a harmless command approval request
          [--file-approval-cancel]      Cancel a disposable file-change request
      """)
  }
}

extension CodexMicroSpike {
  /// Proves the two app-server calls Phase 2 wrote to the documented
  /// architecture but never confirmed: the `workspaceWrite` form of
  /// `turn/start`, and `turn/steer` in full.
  ///
  /// Steps 2.10 and 2.11 both recorded these as unverified, and Step 2.11
  /// went further: `turn/steer` appears nowhere in this repository's proven
  /// surface, so the steering path might not work at all. A probe is the only
  /// thing that settles it.
  ///
  /// **It drives the production types, not a hand-rolled copy.** The request
  /// bodies come from `PhoneTurnPolicy.turnStartParameters` and
  /// `LiveCodexRuntimeSession.steerTurn`, so what is confirmed here is the
  /// exact wire shape the bridge sends. A probe that rebuilt the JSON would
  /// prove only that *some* shape works.
  ///
  /// Isolation: an ephemeral thread rooted in a fresh temporary directory,
  /// which is also the only writable root. Network access is off and the
  /// approval policy is `untrusted`, so the turn cannot reach the network or
  /// escalate. The directory is removed afterwards.
  static func runSteerProbe(
    client: CodexAppServerClient,
    arguments: [String]
  ) async throws {
    guard arguments == ["--confirm-live-turn"] else {
      throw SpikeError.liveTurnConfirmationRequired
    }

    let scratch = URL(fileURLWithPath: NSTemporaryDirectory())
      .appendingPathComponent("codex-micro-steer-probe-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: scratch) }
    let root = scratch.path

    let threadResponse = try await client.request(
      method: "thread/start",
      params: .object([
        "ephemeral": .bool(true),
        "cwd": .string(root),
        "approvalPolicy": .string("untrusted"),
        "sandbox": .string("workspace-write"),
        "serviceName": .string("codex_micro_phase2_steer_probe"),
      ])
    )
    guard let threadID = threadResponse["thread"]["id"].string else {
      throw SpikeError.missingResponseID("thread/start")
    }

    // The production policy, resolved exactly as the gateway resolves it for a
    // device whose effective profile permits workspace work.
    let policy = PhoneTurnPolicy.resolve(
      effectiveProfile: .runWorkspace,
      writableRoots: [root]
    )
    let session = LiveCodexRuntimeSession(client: client)

    let turnID = try await session.startTurn(
      threadID: threadID,
      prompt: "Without using tools or reading files, write a detailed 2,000-word "
        + "explanation of how event-driven clients recover from a dropped connection.",
      policy: policy
    )

    try await TurnEventRecorder.waitUntilStarted(events: client.events, turnID: turnID)

    var steerAccepted = false
    var steerFailure: String?
    do {
      try await session.steerTurn(
        threadID: threadID,
        turnID: turnID,
        prompt: "Stop and reply with the single word: steered."
      )
      steerAccepted = true
    } catch {
      steerFailure = "\(error)"
    }

    try? await client.interruptTurn(threadID: threadID, turnID: turnID)

    print("Codex Micro Phase 2 steer probe")
    print("  isolation: ephemeral thread, fresh temp root, network-disabled")
    print("  sandbox requested: \(policy.sandbox.rawValue)")
    print("  writable roots: \(policy.writableRoots.count)")
    print("  turn/start (workspaceWrite form): accepted, turn \(turnID)")
    if steerAccepted {
      print("  turn/steer: accepted")
    } else {
      print("  turn/steer: REFUSED — \(steerFailure ?? "unknown")")
    }
  }
}

private enum SpikeError: Error, LocalizedError {
  case unknownCommand(String)
  case invalidLimit
  case liveTurnConfirmationRequired
  case missingResponseID(String)
  case conflictingSmokeTurnModes
  case approvalRequestNotObserved(String)
  case existingThreadConfirmationRequired
  case noRecentThread
  case persistedThreadConfirmationRequired
  case restartRecoveryMismatch(turnCount: Int)

  var errorDescription: String? {
    switch self {
    case .unknownCommand(let command):
      "Unknown command: \(command). Run with --help."
    case .invalidLimit:
      "--limit must be an integer from 1 through 100."
    case .liveTurnConfirmationRequired:
      "Live turns consume Codex allowance. Re-run with --confirm-live-turn."
    case .missingResponseID(let method):
      "Codex response to \(method) did not include the required ID."
    case .conflictingSmokeTurnModes:
      "Choose only one smoke-turn mode."
    case .approvalRequestNotObserved(let status):
      "The approval probe ended with status \(status) without an approval request."
    case .existingThreadConfirmationRequired:
      "Resuming loads an existing Codex thread. Re-run with --confirm-existing-thread."
    case .noRecentThread:
      "No recent Codex thread is available to resume."
    case .persistedThreadConfirmationRequired:
      "The restart probe creates and archives a test thread. Re-run with "
        + "--confirm-persisted-test-thread."
    case .restartRecoveryMismatch(let turnCount):
      "Restart recovery returned \(turnCount) turns; expected exactly one."
    }
  }
}
