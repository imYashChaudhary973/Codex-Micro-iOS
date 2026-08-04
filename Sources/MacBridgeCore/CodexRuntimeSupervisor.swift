import CodexAppServer
import Foundation

public enum CodexRuntimeFailure: Equatable, Sendable {
  case compatibilityCheckFailed
  case startupFailed
  case connectionClosed
}

public enum CodexRuntimeRequestError: Error, Equatable, Sendable {
  case notReady
}

public enum CodexRuntimeState: Equatable, Sendable {
  case stopped
  case checkingCompatibility
  case unsupported(CodexCompatibilityDecision)
  case starting
  case ready(CodexCompatibilityReport)
  case degraded(CodexRuntimeFailure)
}

public protocol CodexRuntimeSession: Sendable {
  var events: AsyncStream<AppServerEvent> { get }

  func start() async throws
  func stop() async

  /// Reads one thread with its turns and returns the raw authoritative
  /// thread object, used to rebuild state after a restart.
  func readThread(threadID: String, includeTurns: Bool) async throws -> JSONValue

  /// Sends an explicitly prepared response to a server-initiated request.
  func respondToServerRequest(id: Int64, result: JSONValue) async throws

  /// Interrupts exactly one turn.
  func interruptTurn(threadID: String, turnID: String) async throws

  /// Opens a thread and returns its opaque identifier.
  ///
  /// Invokes no model and consumes no allowance — it opens a conversation
  /// rather than running one, which is why it sits on this seam alongside the
  /// operations that do.
  func startThread(projectID: String, policy: PhoneTurnPolicy) async throws -> String

  /// Starts exactly one phone-originated turn under bridge-resolved settings
  /// and returns its opaque turn identifier.
  func startTurn(
    threadID: String,
    prompt: String,
    policy: PhoneTurnPolicy
  ) async throws -> String

  /// Steers exactly one in-progress turn with additional prompt text.
  ///
  /// Steering never widens a turn's policy: the turn keeps the sandbox,
  /// roots, network, and approval settings it was started with, and this
  /// call carries no policy fields at all.
  func steerTurn(threadID: String, turnID: String, prompt: String) async throws
}

public struct LiveCodexRuntimeSession: CodexRuntimeSession {
  private let client: CodexAppServerClient

  public var events: AsyncStream<AppServerEvent> { client.events }

  public init(client: CodexAppServerClient) {
    self.client = client
  }

  public func start() async throws {
    _ = try await client.start()
  }

  public func stop() async {
    await client.stop()
  }

  public func readThread(threadID: String, includeTurns: Bool = true) async throws -> JSONValue {
    let response = try await client.request(
      method: "thread/read",
      params: .object([
        "threadId": .string(threadID),
        // A thread that has had no user message is "not materialized" and
        // refuses this outright, so a freshly opened one could never be read
        // — and therefore never entered the store, never reached a snapshot,
        // and never appeared on any device. Asking for turns is right when
        // rebuilding a thread that has them and wrong when adopting one that
        // does not, so the caller says which.
        "includeTurns": .bool(includeTurns),
      ])
    )
    return response["thread"]
  }

  public func respondToServerRequest(id: Int64, result: JSONValue) async throws {
    try await client.respondToServerRequest(id: id, result: result)
  }

  public func interruptTurn(threadID: String, turnID: String) async throws {
    try await client.interruptTurn(threadID: threadID, turnID: turnID)
  }

  public func startThread(projectID: String, policy: PhoneTurnPolicy) async throws -> String {
    // cwd and sandbox come from the policy the Mac resolved. The phone names
    // a project it already has a grant for; it never names a path.
    var parameters: [String: JSONValue] = [
      "ephemeral": .bool(false),
      "approvalPolicy": .string(policy.approvalPolicy.rawValue),
      "sandbox": .string(policy.sandbox == .workspaceWrite ? "workspace-write" : "read-only"),
    ]
    if let root = policy.writableRoots.first {
      parameters["cwd"] = .string(root)
    }
    let response = try await client.request(
      method: "thread/start", params: .object(parameters))
    guard let threadID = response["thread"]["id"].string, !threadID.isEmpty else {
      throw CodexRuntimeRequestError.notReady
    }
    return threadID
  }

  /// Starts one turn under settings the bridge resolved. The parameters come
  /// entirely from ``PhoneTurnPolicy``; the only phone-supplied value is the
  /// prompt, which travels as typed text content.
  public func startTurn(
    threadID: String,
    prompt: String,
    policy: PhoneTurnPolicy
  ) async throws -> String {
    let response = try await client.request(
      method: "turn/start",
      params: policy.turnStartParameters(threadID: threadID, prompt: prompt)
    )
    guard let turnID = response["turn"]["id"].string, !turnID.isEmpty else {
      throw CodexRuntimeRequestError.notReady
    }
    return turnID
  }

  /// Steers one in-progress turn.
  ///
  /// The request carries exactly the turn's identity and the new input. It
  /// deliberately carries **no** sandbox, approval, root, or network field:
  /// a steered turn keeps the policy it was started under, so steering can
  /// never widen it.
  ///
  /// **The field is `expectedTurnId`, not `turnId`.** Step 2.11 wrote this
  /// call from the documented architecture and recorded that it was proven
  /// nowhere; the Step 2.14 live probe found Codex 0.146.0 rejecting it with
  /// `missing field expectedTurnId`. Every steer would have failed.
  ///
  /// The name is not a spelling detail. `expectedTurnId` makes the call a
  /// compare-and-swap: Codex refuses the steer unless that turn is still the
  /// thread's current one. Steering a turn that already finished, or one
  /// replaced by a newer turn, is therefore refused by Codex itself rather
  /// than silently applying to whatever is running now — which is the
  /// stronger guarantee, and one the bridge gets for free.
  public func steerTurn(threadID: String, turnID: String, prompt: String) async throws {
    _ = try await client.request(
      method: "turn/steer",
      params: .object([
        "threadId": .string(threadID),
        "expectedTurnId": .string(turnID),
        "input": .array([
          .object(["type": .string("text"), "text": .string(prompt)])
        ]),
      ])
    )
  }
}

public actor CodexRuntimeSupervisor {
  public nonisolated let states: AsyncStream<CodexRuntimeState>
  public nonisolated let events: AsyncStream<AppServerEvent>

  private let policy: CodexCompatibilityPolicy
  private let prober: any CodexCompatibilityProbing
  private let makeSession: @Sendable () -> any CodexRuntimeSession
  private let stateContinuation: AsyncStream<CodexRuntimeState>.Continuation
  private let eventContinuation: AsyncStream<AppServerEvent>.Continuation
  private var currentState: CodexRuntimeState = .stopped
  private var session: (any CodexRuntimeSession)?
  private var monitorTask: Task<Void, Never>?
  private var stopping = false

  public init(
    policy: CodexCompatibilityPolicy,
    prober: any CodexCompatibilityProbing,
    makeSession: @escaping @Sendable () -> any CodexRuntimeSession
  ) {
    self.policy = policy
    self.prober = prober
    self.makeSession = makeSession
    let statePair = AsyncStream<CodexRuntimeState>.makeStream()
    states = statePair.stream
    stateContinuation = statePair.continuation
    let eventPair = AsyncStream<AppServerEvent>.makeStream()
    events = eventPair.stream
    eventContinuation = eventPair.continuation
    stateContinuation.yield(.stopped)
  }

  public static func live(
    policy: CodexCompatibilityPolicy = .phase1
  ) throws -> CodexRuntimeSupervisor {
    let executableURL = try CodexExecutableLocator.locate()
    return CodexRuntimeSupervisor(
      policy: policy,
      prober: SystemCodexCompatibilityProbe(codexExecutableURL: executableURL),
      makeSession: {
        LiveCodexRuntimeSession(
          client: CodexAppServerClient(
            transport: ProcessJSONLineTransport(codexExecutableURL: executableURL)
          )
        )
      }
    )
  }

  public func state() -> CodexRuntimeState {
    currentState
  }

  /// Reads one authoritative thread through the active session. Fails closed
  /// when the runtime is not ready.
  public func readThread(threadID: String, includeTurns: Bool = true) async throws -> JSONValue {
    try await readySession().readThread(threadID: threadID, includeTurns: includeTurns)
  }

  public func respondToServerRequest(id: Int64, result: JSONValue) async throws {
    try await readySession().respondToServerRequest(id: id, result: result)
  }

  public func interruptTurn(threadID: String, turnID: String) async throws {
    try await readySession().interruptTurn(threadID: threadID, turnID: turnID)
  }

  public func steerTurn(threadID: String, turnID: String, prompt: String) async throws {
    try await readySession().steerTurn(threadID: threadID, turnID: turnID, prompt: prompt)
  }

  func readySession() throws -> any CodexRuntimeSession {
    guard case .ready = currentState, let session else {
      throw CodexRuntimeRequestError.notReady
    }
    return session
  }

  public func start() async {
    guard currentState != .checkingCompatibility, currentState != .starting,
      session == nil
    else { return }

    stopping = false
    transition(to: .checkingCompatibility)
    let report: CodexCompatibilityReport
    do {
      report = try await prober.probe()
    } catch {
      transition(to: .degraded(.compatibilityCheckFailed))
      return
    }

    let decision = policy.evaluate(report)
    guard decision == .supported else {
      transition(to: .unsupported(decision))
      return
    }

    transition(to: .starting)
    let newSession = makeSession()
    do {
      try await newSession.start()
    } catch {
      await newSession.stop()
      transition(to: .degraded(.startupFailed))
      return
    }

    session = newSession
    transition(to: .ready(report))
    let stream = newSession.events
    monitorTask = Task { [weak self] in
      for await event in stream {
        guard !Task.isCancelled else { return }
        await self?.forward(event)
      }
      guard !Task.isCancelled else { return }
      await self?.sessionEnded()
    }
  }

  public func stop() async {
    stopping = true
    monitorTask?.cancel()
    monitorTask = nil
    let activeSession = session
    session = nil
    await activeSession?.stop()
    transition(to: .stopped)
  }

  private func forward(_ event: AppServerEvent) {
    eventContinuation.yield(event)
  }

  private func sessionEnded() {
    session = nil
    monitorTask = nil
    if stopping {
      transition(to: .stopped)
    } else {
      transition(to: .degraded(.connectionClosed))
    }
  }

  private func transition(to state: CodexRuntimeState) {
    guard currentState != state else { return }
    currentState = state
    stateContinuation.yield(state)
  }
}
