import CodexAppServer
import Foundation

final class MockJSONLineTransport: JSONLineTransport, @unchecked Sendable {
  let lines: AsyncThrowingStream<Data, Error>

  private let continuation: AsyncThrowingStream<Data, Error>.Continuation
  private let lock = NSLock()
  private var sentMessages: [JSONValue] = []
  private let responder: @Sendable (JSONValue) -> JSONValue?

  init(responder: @escaping @Sendable (JSONValue) -> JSONValue?) {
    self.responder = responder
    let pair = AsyncThrowingStream<Data, Error>.makeStream()
    lines = pair.stream
    continuation = pair.continuation
  }

  func start() throws {}

  func send(_ data: Data) throws {
    let message = try JSONDecoder().decode(JSONValue.self, from: data)
    lock.lock()
    sentMessages.append(message)
    lock.unlock()

    if let response = responder(message) {
      continuation.yield(try JSONEncoder().encode(response))
    }
  }

  func stop() {
    continuation.finish()
  }

  func yield(_ message: JSONValue) throws {
    continuation.yield(try JSONEncoder().encode(message))
  }

  func messages() -> [JSONValue] {
    lock.lock()
    defer { lock.unlock() }
    return sentMessages
  }
}
