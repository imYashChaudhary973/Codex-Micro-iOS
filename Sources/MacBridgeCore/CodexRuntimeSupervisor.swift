import CodexAppServer
import Foundation

public enum CodexRuntimeFailure: Equatable, Sendable {
  case compatibilityCheckFailed
  case startupFailed
  case connectionClosed
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
