import Foundation
import Security

public enum PinnedWebSocketClientError: Error, Equatable {
  case invalidMessage
  case pinMismatch
  case timeout
  case trustUnavailable
}

public final class PinnedWebSocketClient: NSObject, URLSessionDelegate, @unchecked Sendable {
  private enum Failure: Equatable, Sendable {
    case none
    case pinMismatch
    case timeout
    case trustUnavailable
  }

  private let expectedSPKISHA256: Data
  private let lock = NSLock()
  private var failure = Failure.none
  private lazy var session = URLSession(
    configuration: .ephemeral,
    delegate: self,
    delegateQueue: nil
  )

  public init(expectedSPKISHA256: Data) {
    self.expectedSPKISHA256 = expectedSPKISHA256
    super.init()
  }

  public func exchange(url: URL, message: Data) async throws -> Data {
    var request = URLRequest(url: url)
    request.timeoutInterval = 5
    request.setValue(HardenedWebSocketPolicy.origin, forHTTPHeaderField: "Origin")
    request.setValue(
      HardenedWebSocketPolicy.subprotocol,
      forHTTPHeaderField: "Sec-WebSocket-Protocol"
    )
    request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
    let task = session.webSocketTask(with: request)
    task.resume()
    defer {
      task.cancel(with: .normalClosure, reason: nil)
      session.invalidateAndCancel()
    }
    let timeoutTask = Task { [weak self] in
      try await Task.sleep(for: .seconds(5))
      self?.recordFailure(.timeout)
      task.cancel(with: .goingAway, reason: nil)
    }
    defer { timeoutTask.cancel() }

    do {
      try await task.send(.data(message))
      switch try await task.receive() {
      case .data(let response):
        return response
      case .string:
        throw PinnedWebSocketClientError.invalidMessage
      @unknown default:
        throw PinnedWebSocketClientError.invalidMessage
      }
    } catch {
      switch lock.withLock({ failure }) {
      case .pinMismatch:
        throw PinnedWebSocketClientError.pinMismatch
      case .timeout:
        throw PinnedWebSocketClientError.timeout
      case .trustUnavailable:
        throw PinnedWebSocketClientError.trustUnavailable
      case .none:
        throw error
      }
    }
  }

  public func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler:
      @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      let trust = challenge.protectionSpace.serverTrust,
      let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
      let certificate = chain.first,
      let publicKey = SecCertificateCopyKey(certificate),
      let spki = try? P256SPKI.der(publicKey: publicKey)
    else {
      recordFailure(.trustUnavailable)
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    let presentedPin = P256SPKI.sha256(spki)
    guard P256SPKI.matches(presentedPin, expectedSPKISHA256) else {
      recordFailure(.pinMismatch)
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }

  private func recordFailure(_ failure: Failure) {
    lock.withLock {
      guard self.failure == .none else { return }
      self.failure = failure
    }
  }
}
