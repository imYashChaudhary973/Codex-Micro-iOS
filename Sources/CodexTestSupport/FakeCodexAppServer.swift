import CodexAppServer
import Foundation

/// A scripted JSON-RPC reply for one client request.
public enum FakeAppServerReply: Sendable {
  case result(JSONValue)
  case error(code: Int64, message: String)
  /// Never answer, so the client's request timeout path is exercised.
  case silence
}

/// A scripted reply plus JSON-RPC messages the server emits immediately after
/// it, in order. Follow-ups let one stub model "accept turn/start, then stream
/// turn/started" deterministically.
public struct FakeAppServerExchange: Sendable {
  public let reply: FakeAppServerReply
  public let followUps: [JSONValue]

  public init(reply: FakeAppServerReply, followUps: [JSONValue] = []) {
    self.reply = reply
    self.followUps = followUps
  }

  public static func result(_ value: JSONValue, followUps: [JSONValue] = []) -> Self {
    .init(reply: .result(value), followUps: followUps)
  }

  public static func error(code: Int64, message: String) -> Self {
    .init(reply: .error(code: code, message: message))
  }

  public static var silence: Self { .init(reply: .silence) }
}

/// Deterministic scripted stand-in for `codex app-server` behind the
/// `JSONLineTransport` seam.
///
/// Unstubbed request methods fail closed with a JSON-RPC method-not-found
/// error so tests surface every unexpected client call. `initialize` is
/// stubbed with a fixture result by default and can be overridden. All client
/// traffic is recorded and queryable by message kind, including the responses
/// a client sends to server-initiated requests — the assertion surface for
/// "approvals are never answered automatically".
public final class FakeCodexAppServer: JSONLineTransport, @unchecked Sendable {
  public typealias RequestHandler = @Sendable (Int64, JSONValue) -> FakeAppServerExchange

  public let lines: AsyncThrowingStream<Data, Error>

  private let continuation: AsyncThrowingStream<Data, Error>.Continuation
  private let lock = NSLock()
  private var handlers: [String: RequestHandler]
  private var responseFollowUps: [Int64: [JSONValue]] = [:]
  private var received: [JSONValue] = []
  private var finished = false

  public init() {
    let pair = AsyncThrowingStream<Data, Error>.makeStream()
    lines = pair.stream
    continuation = pair.continuation
    handlers = [
      "initialize": { _, _ in .result(CodexAppServerFixtures.initializeResult()) }
    ]
  }

  // MARK: - Scripting

  public func stub(_ method: String, handler: @escaping RequestHandler) {
    lock.lock()
    handlers[method] = handler
    lock.unlock()
  }

  public func stubResult(_ method: String, _ result: JSONValue, followUps: [JSONValue] = []) {
    stub(method) { _, _ in .result(result, followUps: followUps) }
  }

  /// Emits the given messages the instant the client responds to the
  /// server-initiated request with this RPC ID — the tightest possible race
  /// between a sent response and its confirmation notification.
  public func onServerRequestResponse(rpcID: Int64, emit followUps: [JSONValue]) {
    lock.lock()
    responseFollowUps[rpcID] = followUps
    lock.unlock()
  }

  /// Emits a complete JSON-RPC message (notification or server request) to
  /// the client, exactly as the real app-server would over stdout.
  public func emit(_ message: JSONValue) throws {
    continuation.yield(try JSONEncoder().encode(message))
  }

  /// Emits raw bytes that need not be valid JSON, for malformed-line cases.
  public func emitRaw(_ data: Data) {
    continuation.yield(data)
  }

  /// Ends the stream cleanly, as if the process closed stdout.
  public func closeCleanly() {
    finish(error: nil)
  }

  /// Ends the stream with a process-exit error, as if Codex crashed.
  public func crash(exitStatus: Int32 = 1) {
    finish(error: CodexAppServerError.processExited(status: exitStatus))
  }

  // MARK: - Recorded client traffic

  public func messages() -> [JSONValue] {
    lock.lock()
    defer { lock.unlock() }
    return received
  }

  /// Client requests (method and id) for one method.
  public func requests(_ method: String) -> [JSONValue] {
    messages().filter { $0["method"].string == method && $0["id"].integer != nil }
  }

  /// Client notifications (method, no id) for one method.
  public func notifications(_ method: String) -> [JSONValue] {
    messages().filter { $0["method"].string == method && $0["id"].integer == nil }
  }

  /// Every response the client sent to a server-initiated request
  /// (id, no method). Empty means the client answered nothing.
  public func serverRequestResponses() -> [JSONValue] {
    messages().filter { $0["method"].string == nil && $0["id"].integer != nil }
  }

  public func serverRequestResponse(rpcID: Int64) -> JSONValue? {
    serverRequestResponses().first { $0["id"].integer == rpcID }
  }

  // MARK: - JSONLineTransport

  public func start() throws {}

  public func send(_ data: Data) throws {
    let message = try JSONDecoder().decode(JSONValue.self, from: data)
    lock.lock()
    received.append(message)
    lock.unlock()

    guard let method = message["method"].string else {
      if let responseID = message["id"].integer {
        lock.lock()
        let followUps = responseFollowUps.removeValue(forKey: responseID)
        lock.unlock()
        for followUp in followUps ?? [] {
          try emit(followUp)
        }
      }
      return
    }
    guard let id = message["id"].integer else { return }

    lock.lock()
    let handler = handlers[method]
    lock.unlock()

    let exchange =
      handler?(id, message["params"])
      ?? .error(code: -32601, message: "Method not found")
    switch exchange.reply {
    case .result(let result):
      try emit(.object(["id": .integer(id), "result": result]))
    case .error(let code, let errorMessage):
      try emit(
        .object([
          "id": .integer(id),
          "error": .object([
            "code": .integer(code),
            "message": .string(errorMessage),
          ]),
        ]))
    case .silence:
      break
    }
    for followUp in exchange.followUps {
      try emit(followUp)
    }
  }

  public func stop() {
    finish(error: nil)
  }

  private func finish(error: Error?) {
    lock.lock()
    guard !finished else {
      lock.unlock()
      return
    }
    finished = true
    lock.unlock()

    if let error {
      continuation.finish(throwing: error)
    } else {
      continuation.finish()
    }
  }
}
