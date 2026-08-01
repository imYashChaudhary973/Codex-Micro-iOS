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
  func readThread(threadID: String) async throws -> JSONValue

  /// Sends an explicitly prepared response to a server-initiated request.
  func respondToServerRequest(id: Int64, result: JSONValue) async throws

  /// Interrupts exactly one turn.
  func interruptTurn(threadID: String, turnID: String) async throws
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

  public func readThread(threadID: String) async throws -> JSONValue {
    let response = try await client.request(
      method: "thread/read",
      params: .object([
        "threadId": .string(threadID),
        "includeTurns": .bool(true),
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
  public func readThread(threadID: String) async throws -> JSONValue {
    try await readySession().readThread(threadID: threadID)
  }

  public func respondToServerRequest(id: Int64, result: JSONValue) async throws {
    try await readySession().respondToServerRequest(id: id, result: result)
  }

  public func interruptTurn(threadID: String, turnID: String) async throws {
    try await readySession().interruptTurn(threadID: threadID, turnID: turnID)
  }

  private func readySession() throws -> any CodexRuntimeSession {
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
