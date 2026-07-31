import Foundation

public protocol JSONLineTransport: Sendable {
  var lines: AsyncThrowingStream<Data, Error> { get }

  func start() throws
  func send(_ data: Data) throws
  func stop()
}

public final class ProcessJSONLineTransport: JSONLineTransport, @unchecked Sendable {
  public let lines: AsyncThrowingStream<Data, Error>

  private let continuation: AsyncThrowingStream<Data, Error>.Continuation
  private let lock = NSLock()
  private var buffer = Data()
  private var process: Process?
  private var input: FileHandle?
  private var output: FileHandle?
  private var finished = false
  private let executableURL: URL
  private let arguments: [String]

  public init(codexExecutableURL: URL? = nil) {
    if let codexExecutableURL {
      executableURL = codexExecutableURL
      arguments = ["app-server", "--stdio"]
    } else {
      executableURL = URL(fileURLWithPath: "/usr/bin/env")
      arguments = ["codex", "app-server", "--stdio"]
    }
    let pair = AsyncThrowingStream<Data, Error>.makeStream()
    lines = pair.stream
    continuation = pair.continuation
  }

  public func start() throws {
    lock.lock()
    defer { lock.unlock() }

    guard process == nil else { return }
    guard !finished else { throw CodexAppServerError.transportClosed }

    let process = Process()
    let inputPipe = Pipe()
    let outputPipe = Pipe()

    process.executableURL = executableURL
    process.arguments = arguments
    process.standardInput = inputPipe
    process.standardOutput = outputPipe
    process.standardError = FileHandle.standardError

    let output = outputPipe.fileHandleForReading
    output.readabilityHandler = { [weak self] handle in
      self?.consume(handle.availableData)
    }
    process.terminationHandler = { [weak self] process in
      self?.finish(
        error: CodexAppServerError.processExited(status: process.terminationStatus)
      )
    }

    try process.run()
    self.process = process
    input = inputPipe.fileHandleForWriting
    self.output = output
  }

  public func send(_ data: Data) throws {
    lock.lock()
    let input = input
    let isFinished = finished
    lock.unlock()

    guard !isFinished, let input else {
      throw CodexAppServerError.transportClosed
    }

    var line = data
    line.append(0x0A)
    try input.write(contentsOf: line)
  }

  public func stop() {
    lock.lock()
    let process = process
    let input = input
    let output = output
    self.process = nil
    self.input = nil
    self.output = nil
    lock.unlock()

    output?.readabilityHandler = nil
    try? input?.close()
    try? output?.close()
    if process?.isRunning == true {
      process?.terminate()
    }
    finish(error: nil)
  }

  private func consume(_ data: Data) {
    guard !data.isEmpty else {
      finish(error: nil)
      return
    }

    lock.lock()
    guard !finished else {
      lock.unlock()
      return
    }

    buffer.append(data)
    var completeLines: [Data] = []
    while let newline = buffer.firstIndex(of: 0x0A) {
      var line = Data(buffer[..<newline])
      buffer.removeSubrange(...newline)
      if line.last == 0x0D {
        line.removeLast()
      }
      if !line.isEmpty {
        completeLines.append(line)
      }
    }
    lock.unlock()

    for line in completeLines {
      continuation.yield(line)
    }
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
