import Foundation
import Network

/// Finds the paired Mac on the local network.
///
/// **The stored endpoint is a hint, not an address.** Pairing records where
/// the Mac was, but the listener binds an ephemeral port, so that address is
/// stale the moment the bridge restarts. Reconnecting by remembering a port
/// therefore works exactly once — which is why the phone appeared to pair and
/// then never connect again.
///
/// Discovery is safe precisely because it is not trusted. The device pins the
/// Mac's TLS SPKI and its long-term identity key at pairing; browsing only
/// decides *where to look*. A wrong or hostile answer produces a TLS failure
/// rather than a connection to the wrong Mac, which is what lets this be a
/// plain unauthenticated mDNS lookup.
public enum BridgeDiscovery {
  /// The service the Mac advertises. Duplicated from `ListenerBonjourRecord`
  /// for the same reason the upgrade values are: `MacBridgeServer` is
  /// macOS-only, and a Mac-side test asserts both literals.
  public static let serviceType = "_codexmicro._tcp"
  public static let domain = "local."

  public struct Endpoint: Equatable, Sendable {
    public let host: String
    public let port: Int
  }

  /// Browses for the bridge and resolves the first result.
  ///
  /// **The timeout lives inside the continuation, not in a racing task.** A
  /// task group waits for every child before returning, and `cancelAll()`
  /// cannot unblock a `withCheckedContinuation` that simply never resumes. So
  /// racing a browse against a sleeping task deadlocks the moment the browse
  /// finds nothing — the ordinary case when the Mac is asleep or on another
  /// network. That is exactly how this hung: the phone reported it was paired
  /// and then stopped, with the screen saying only "not connected".
  ///
  /// Returns `nil` on timeout rather than throwing, because not finding a Mac
  /// is ordinary and a thrown error would make the common path look
  /// exceptional.
  public static func find(timeout: Duration = .seconds(6)) async -> Endpoint? {
    await withCheckedContinuation { continuation in
      let resumed = ResumeOnce(continuation)
      let seconds = Double(timeout.components.seconds)
      DispatchQueue.global().asyncAfter(deadline: .now() + seconds) {
        resumed.finish(nil)
      }
      browse(resumed)
    }
  }

  private static func browse(_ resumed: ResumeOnce) {
    let parameters = NWParameters.tcp
    parameters.includePeerToPeer = false
    let browser = NWBrowser(
      for: .bonjour(type: serviceType, domain: domain), using: parameters)

    browser.browseResultsChangedHandler = { results, _ in
      guard let result = results.first else { return }
      // A browse result names the service. Resolving it to an address means
      // establishing a connection, which Network.framework does as part of
      // reaching `.ready`.
      let connection = NWConnection(to: result.endpoint, using: parameters)
      connection.stateUpdateHandler = { state in
        switch state {
        case .ready:
          if let resolved = connection.currentPath?.remoteEndpoint,
            case .hostPort(let host, let port) = resolved
          {
            resumed.finish(Endpoint(host: describe(host), port: Int(port.rawValue)))
          } else {
            resumed.finish(nil)
          }
          connection.cancel()
          browser.cancel()
        case .failed, .cancelled:
          connection.cancel()
        default:
          break
        }
      }
      connection.start(queue: .global())
    }

    browser.stateUpdateHandler = { state in
      if case .failed = state {
        resumed.finish(nil)
        browser.cancel()
      }
    }
    browser.start(queue: .global())
  }

  /// A resolved IPv4/IPv6 literal, with the interface suffix stripped.
  ///
  /// A link-local address arrives as `fe80::1%en0`; the percent-scope is
  /// meaningful to the resolver and meaningless in a URL, so it is removed
  /// rather than passed through to fail later as a malformed host.
  static func describe(_ host: NWEndpoint.Host) -> String {
    switch host {
    case .ipv4(let address): return "\(address)".components(separatedBy: "%")[0]
    case .ipv6(let address): return "\(address)".components(separatedBy: "%")[0]
    case .name(let name, _): return name
    @unknown default: return ""
    }
  }
}

/// Resumes a continuation exactly once.
///
/// Browse results, connection states, and the timeout can all fire more than
/// once and in any order. Resuming a continuation twice is a crash rather than
/// a warning, so the guard is not optional.
private final class ResumeOnce: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<BridgeDiscovery.Endpoint?, Never>?

  init(_ continuation: CheckedContinuation<BridgeDiscovery.Endpoint?, Never>) {
    self.continuation = continuation
  }

  func finish(_ value: BridgeDiscovery.Endpoint?) {
    lock.lock()
    let pending = continuation
    continuation = nil
    lock.unlock()
    pending?.resume(returning: value)
  }
}
