import Foundation

public struct CodexRPCError: Error, LocalizedError, Equatable, Sendable {
  public let code: Int64?
  public let message: String
  public let data: JSONValue?

  public var errorDescription: String? { message }
}

public enum CodexAppServerError: Error, LocalizedError, Equatable, Sendable {
  case invalidMessage
  case notStarted
  case alreadyStarted
  case processExited(status: Int32)
  case requestTimedOut(method: String)
  case transportClosed

  public var errorDescription: String? {
    switch self {
    case .invalidMessage:
      "Codex app-server sent an invalid JSON-RPC message."
    case .notStarted:
      "Codex app-server client is not initialized."
    case .alreadyStarted:
      "Codex app-server client was already started."
    case .processExited(let status):
      "Codex app-server exited with status \(status)."
    case .requestTimedOut(let method):
      "Codex request \(method) timed out."
    case .transportClosed:
      "Codex app-server transport is closed."
    }
  }
}

public enum AppServerEvent: Equatable, Sendable {
  case notification(method: String, params: JSONValue)
  case serverRequest(id: Int64, method: String, params: JSONValue)
  case protocolWarning(String)
}

public actor CodexAppServerClient {
  public nonisolated let events: AsyncStream<AppServerEvent>

  private enum State {
    case idle
    case starting
    case ready
    case stopped
  }

  private struct PendingRequest {
    let method: String
    let continuation: CheckedContinuation<JSONValue, Error>
  }

  private let transport: any JSONLineTransport
  private let timeout: Duration
  private let eventContinuation: AsyncStream<AppServerEvent>.Continuation
  private var state = State.idle
  private var nextID: Int64 = 1
  private var pending: [Int64: PendingRequest] = [:]
  private var readerTask: Task<Void, Never>?

  public init(
    transport: any JSONLineTransport = ProcessJSONLineTransport(),
    timeout: Duration = .seconds(10)
  ) {
    self.transport = transport
    self.timeout = timeout
    let pair = AsyncStream<AppServerEvent>.makeStream()
    events = pair.stream
    eventContinuation = pair.continuation
  }

  @discardableResult
  public func start() async throws -> JSONValue {
    guard state == .idle else { throw CodexAppServerError.alreadyStarted }
    state = .starting

    do {
      try transport.start()
      startReader()

      let result = try await sendRequest(
        method: "initialize",
        params: .object([
          "clientInfo": .object([
            "name": .string("codex_micro_spike"),
            "title": .string("Codex Micro Phase 0 Spike"),
            "version": .string("0.1.0"),
          ])
        ])
      )
      try sendNotification(method: "initialized", params: .object([:]))
      state = .ready
      return result
    } catch {
      state = .stopped
      transport.stop()
      failAllPending(with: error)
      throw error
    }
  }

  public func request(method: String, params: JSONValue? = nil) async throws -> JSONValue {
    guard state == .ready else { throw CodexAppServerError.notStarted }
    return try await sendRequest(method: method, params: params)
  }

  public func readThreadSnapshot(threadID: String) async throws -> ThreadRuntimeSnapshot {
    let response = try await request(
      method: "thread/read",
      params: .object([
        "threadId": .string(threadID),
        "includeTurns": .bool(true),
      ])
    )
    return try ThreadRuntimeSnapshot(thread: response["thread"])
  }

  public func respondToServerRequest(id: Int64, result: JSONValue) throws {
    guard state == .ready else { throw CodexAppServerError.notStarted }
    let message = JSONValue.object([
      "id": .integer(id),
      "result": result,
    ])
    try transport.send(JSONEncoder().encode(message))
  }

  public func stop() {
    guard state != .stopped else { return }
    state = .stopped
    readerTask?.cancel()
    readerTask = nil
    transport.stop()
    failAllPending(with: CodexAppServerError.transportClosed)
    eventContinuation.finish()
  }

  private func startReader() {
    let transport = transport
    readerTask = Task { [weak self] in
      do {
        for try await line in transport.lines {
          guard !Task.isCancelled else { break }
          await self?.handle(line)
        }
        await self?.transportEnded(error: CodexAppServerError.transportClosed)
      } catch {
        await self?.transportEnded(error: error)
      }
    }
  }

  private func sendRequest(method: String, params: JSONValue?) async throws -> JSONValue {
    let id = nextID
    nextID += 1

    var message: [String: JSONValue] = [
      "id": .integer(id),
      "method": .string(method),
    ]
    if let params {
      message["params"] = params
    }

    let data = try JSONEncoder().encode(JSONValue.object(message))

    return try await withCheckedThrowingContinuation { continuation in
      pending[id] = PendingRequest(method: method, continuation: continuation)

      do {
        try transport.send(data)
      } catch {
        pending.removeValue(forKey: id)?.continuation.resume(throwing: error)
        return
      }

      Task { [weak self, timeout] in
        try? await Task.sleep(for: timeout)
        await self?.timeOutRequest(id: id)
      }
    }
  }

  private func sendNotification(method: String, params: JSONValue) throws {
    let message = JSONValue.object([
      "method": .string(method),
      "params": params,
    ])
    try transport.send(JSONEncoder().encode(message))
  }

  private func handle(_ data: Data) {
    guard
      let message = try? JSONDecoder().decode(JSONValue.self, from: data),
      let object = message.object
    else {
      eventContinuation.yield(.protocolWarning("Ignored malformed JSON from app-server."))
      return
    }

    if let id = object["id"]?.integer, let pendingRequest = pending.removeValue(forKey: id) {
      if let error = object["error"]?.object {
        pendingRequest.continuation.resume(
          throwing: CodexRPCError(
            code: error["code"]?.integer,
            message: error["message"]?.string ?? "Codex request failed.",
            data: error["data"]
          )
        )
      } else {
        pendingRequest.continuation.resume(returning: object["result"] ?? .null)
      }
      return
    }

    guard let method = object["method"]?.string else {
      eventContinuation.yield(.protocolWarning("Ignored JSON-RPC message without a method."))
      return
    }

    let params = object["params"] ?? .null
    if let id = object["id"]?.integer {
      eventContinuation.yield(.serverRequest(id: id, method: method, params: params))
    } else {
      eventContinuation.yield(.notification(method: method, params: params))
    }
  }

  private func timeOutRequest(id: Int64) {
    guard let request = pending.removeValue(forKey: id) else { return }
    request.continuation.resume(
      throwing: CodexAppServerError.requestTimedOut(method: request.method)
    )
  }

  private func transportEnded(error: Error) {
    guard state != .stopped else { return }
    state = .stopped
    failAllPending(with: error)
    eventContinuation.finish()
  }

  private func failAllPending(with error: Error) {
    let requests = pending.values
    pending.removeAll()
    for request in requests {
      request.continuation.resume(throwing: error)
    }
  }
}
