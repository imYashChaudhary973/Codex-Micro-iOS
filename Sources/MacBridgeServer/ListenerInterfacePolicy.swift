import Darwin
import Foundation
import NIOCore
import Network
import SystemConfiguration

/// Closed vocabulary of the interface kinds the bind policy recognizes
/// (ADR §8).
///
/// Only ``wifi`` and ``ethernet`` are eligible for a production bind;
/// ``loopback`` is reachable exclusively through
/// ``ListenerInterfaceBinding/testOnlyLoopback()``. Every other kind is
/// denied, so a VPN, tunnel, cellular, or AWDL peer-to-peer interface can
/// never carry the listener.
public enum ListenerInterfaceKind: String, CaseIterable, Sendable {
  /// Wi-Fi (`IEEE80211`).
  case wifi
  /// Wired Ethernet.
  case ethernet
  /// Loopback; test-only.
  case loopback
  /// IPSec/L2TP/PPP style virtual private network.
  case vpn
  /// `utun`/`ipsec`/`gif`/`stf` tunnel.
  case tunnel
  /// WWAN / cellular.
  case cellular
  /// AWDL / `llw` peer-to-peer.
  case peerToPeer
  /// Recognized but unclassified.
  case other
  /// Unspecified/wildcard pseudo-interface.
  case wildcard
}

/// One enumerated local interface, reduced to the flags the policy needs.
///
/// The descriptor carries no address, MAC, vendor, or user-visible name
/// beyond the BSD device identifier, which never reaches a log.
public struct ListenerInterface: Equatable, Sendable {
  /// The BSD device name (`en0`, `lo0`, …).
  public let identifier: String
  /// The classified kind.
  public let kind: ListenerInterfaceKind
  /// `IFF_UP`.
  public let isUp: Bool
  /// `IFF_RUNNING`.
  public let isRunning: Bool
  /// `IFF_POINTOPOINT`.
  public let isPointToPoint: Bool

  /// Creates a descriptor. Callers outside discovery use this only to build
  /// deterministic policy fixtures; a descriptor alone can never produce a
  /// binding, because ``ListenerInterfaceBinding`` revalidates the address.
  public init(
    identifier: String,
    kind: ListenerInterfaceKind,
    isUp: Bool,
    isRunning: Bool,
    isPointToPoint: Bool
  ) {
    self.identifier = identifier
    self.kind = kind
    self.isUp = isUp
    self.isRunning = isRunning
    self.isPointToPoint = isPointToPoint
  }
}

/// Interface eligibility policy (ADR §8).
///
/// The default value is the production policy: loopback is denied. A policy
/// that admits loopback exists only so deterministic tests can bind
/// `127.0.0.1`, and it is never constructed on a production path.
public struct ListenerInterfacePolicy: Equatable, Sendable {
  /// Whether loopback interfaces and loopback addresses are admitted. False
  /// on every production path.
  public let allowLoopbackForTests: Bool

  /// Creates a policy; production callers use the default.
  public init(allowLoopbackForTests: Bool = false) {
    self.allowLoopbackForTests = allowLoopbackForTests
  }

  /// Whether `interface` may carry the listener: it must be up, running,
  /// not point-to-point, and of an eligible kind.
  public func allows(_ interface: ListenerInterface) -> Bool {
    guard interface.isUp, interface.isRunning, !interface.isPointToPoint else { return false }
    switch interface.kind {
    case .wifi, .ethernet:
      return true
    case .loopback:
      return allowLoopbackForTests
    case .vpn, .tunnel, .cellular, .peerToPeer, .other, .wildcard:
      return false
    }
  }
}

/// Closed bind-eligibility failure vocabulary. No case carries an address,
/// interface name, or system error value.
public enum ListenerInterfaceError: Error, Equatable, Sendable {
  /// The address is numeric but not an eligible private/ULA (or admitted
  /// loopback) address for the interface kind.
  case addressDenied
  /// The interface is down, point-to-point, or of a denied kind.
  case interfaceDenied
  /// The address is not a numeric IPv4/IPv6 literal. Hostnames are never
  /// resolved: there is no DNS path into a bind.
  case nonNumericAddress
  /// Enumerating local interfaces failed.
  case enumerationFailed
  /// No interface satisfied the policy.
  case noEligibleInterface
  /// No live `NWInterface` object could be pinned for an eligible binding
  /// (ADR §8/§16 live-object pinning).
  case liveInterfaceUnavailable
}

/// An unforgeable validated bind target (ADR §8).
///
/// There is no public arbitrary initializer: a value exists only because
/// ``ListenerInterfaceDiscovery`` validated a numeric address on an active
/// allowed interface, or because the explicit test-only loopback factory was
/// called. ``revalidated(policy:)`` repeats the full check at startup, so a
/// binding captured while an interface was eligible cannot be replayed after
/// it stops being eligible.
public struct ListenerInterfaceBinding: Equatable, Sendable {
  /// The interface this binding was validated against.
  public let interface: ListenerInterface
  /// The numeric bind address, exactly as validated.
  public let host: String
  /// The pre-parsed bind address; NIOTS binds this value directly, so no
  /// wildcard or DNS fallback exists.
  public let socketAddress: SocketAddress

  private init(interface: ListenerInterface, host: String, socketAddress: SocketAddress) {
    self.interface = interface
    self.host = host
    self.socketAddress = socketAddress
  }

  static func validated(
    interface: ListenerInterface,
    numericAddress: String,
    policy: ListenerInterfacePolicy
  ) throws -> ListenerInterfaceBinding {
    guard policy.allows(interface) else { throw ListenerInterfaceError.interfaceDenied }
    guard ListenerAddressPolicy.isNumeric(numericAddress) else {
      throw ListenerInterfaceError.nonNumericAddress
    }
    guard
      ListenerAddressPolicy.allows(
        numericAddress,
        interfaceKind: interface.kind,
        allowLoopbackForTests: policy.allowLoopbackForTests
      )
    else {
      throw ListenerInterfaceError.addressDenied
    }
    guard let socketAddress = try? SocketAddress(ipAddress: numericAddress, port: 0) else {
      throw ListenerInterfaceError.nonNumericAddress
    }
    return ListenerInterfaceBinding(
      interface: interface,
      host: numericAddress,
      socketAddress: socketAddress
    )
  }

  /// The single explicit loopback factory (ADR §8). It is reachable only
  /// from deterministic tests and the acceptance tooling; production
  /// startup uses a discovery-produced binding and a policy that denies
  /// loopback, so this binding fails revalidation there.
  public static func testOnlyLoopback() throws -> ListenerInterfaceBinding {
    try validated(
      interface: ListenerInterface(
        identifier: "lo0",
        kind: .loopback,
        isUp: true,
        isRunning: true,
        isPointToPoint: false
      ),
      numericAddress: "127.0.0.1",
      policy: ListenerInterfacePolicy(allowLoopbackForTests: true)
    )
  }

  /// Repeats the complete eligibility check against `policy` and returns the
  /// address to bind. Startup calls this independently of binding creation.
  public func revalidated(policy: ListenerInterfacePolicy) throws -> SocketAddress {
    try Self.validated(interface: interface, numericAddress: host, policy: policy).socketAddress
  }
}

/// Numeric-address eligibility (ADR §8): private IPv4 or IPv6 ULA on Wi-Fi or
/// Ethernet, plus admitted loopback. Hostnames, wildcard/unspecified, public,
/// multicast, and IPv4/IPv6 link-local addresses are all denied.
enum ListenerAddressPolicy {
  static func isNumeric(_ address: String) -> Bool {
    var ipv4 = in_addr()
    if inet_pton(AF_INET, address, &ipv4) == 1 { return true }
    var ipv6 = in6_addr()
    return inet_pton(AF_INET6, address, &ipv6) == 1
  }

  static func allows(
    _ address: String,
    interfaceKind: ListenerInterfaceKind,
    allowLoopbackForTests: Bool
  ) -> Bool {
    var ipv4 = in_addr()
    if inet_pton(AF_INET, address, &ipv4) == 1 {
      let value = UInt32(bigEndian: ipv4.s_addr)
      if value & 0xFF00_0000 == 0x7F00_0000 {
        return interfaceKind == .loopback && allowLoopbackForTests
      }
      guard interfaceKind == .wifi || interfaceKind == .ethernet else { return false }
      return value & 0xFF00_0000 == 0x0A00_0000
        || value & 0xFFF0_0000 == 0xAC10_0000
        || value & 0xFFFF_0000 == 0xC0A8_0000
    }

    var ipv6 = in6_addr()
    guard inet_pton(AF_INET6, address, &ipv6) == 1 else { return false }
    return withUnsafeBytes(of: &ipv6) { bytes in
      let isLoopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
      if isLoopback {
        return interfaceKind == .loopback && allowLoopbackForTests
      }
      guard interfaceKind == .wifi || interfaceKind == .ethernet else { return false }
      return (bytes[0] & 0xFE) == 0xFC
    }
  }
}

/// Local-interface enumeration. The only production source of a
/// ``ListenerInterfaceBinding``.
public enum ListenerInterfaceDiscovery {
  /// Every numeric address on an active allowed interface, sorted for
  /// determinism. Ineligible entries are skipped silently: the result set
  /// is the allowlist, never a diagnostic of what was rejected.
  public static func eligibleBindings(
    policy: ListenerInterfacePolicy
  ) throws -> [ListenerInterfaceBinding] {
    let configuredKinds = configuredInterfaceKinds()
    var pointer: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&pointer) == 0, let first = pointer else {
      throw ListenerInterfaceError.enumerationFailed
    }
    defer { freeifaddrs(first) }

    var results: [ListenerInterfaceBinding] = []
    var current: UnsafeMutablePointer<ifaddrs>? = first
    while let entry = current?.pointee {
      defer { current = entry.ifa_next }
      guard let address = entry.ifa_addr else { continue }
      let family = Int32(address.pointee.sa_family)
      guard family == AF_INET || family == AF_INET6 else { continue }

      let name = String(cString: entry.ifa_name)
      let flags = Int32(entry.ifa_flags)
      let descriptor = ListenerInterface(
        identifier: name,
        kind: classify(name: name, flags: flags, configuredKind: configuredKinds[name]),
        isUp: flags & IFF_UP != 0,
        isRunning: flags & IFF_RUNNING != 0,
        isPointToPoint: flags & IFF_POINTOPOINT != 0
      )
      guard let host = numericHost(address),
        let binding = try? ListenerInterfaceBinding.validated(
          interface: descriptor,
          numericAddress: host,
          policy: policy
        )
      else {
        continue
      }
      results.append(binding)
    }
    return results.sorted {
      ($0.interface.identifier, $0.host) < ($1.interface.identifier, $1.host)
    }
  }

  /// The first eligible binding, or ``ListenerInterfaceError/noEligibleInterface``.
  public static func firstEligibleBinding(
    policy: ListenerInterfacePolicy
  ) throws -> ListenerInterfaceBinding {
    guard let binding = try eligibleBindings(policy: policy).first else {
      throw ListenerInterfaceError.noEligibleInterface
    }
    return binding
  }

  private static func configuredInterfaceKinds() -> [String: ListenerInterfaceKind] {
    guard let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [:] }
    let pairs: [(String, ListenerInterfaceKind)] = interfaces.compactMap { interface in
      guard let name = SCNetworkInterfaceGetBSDName(interface) as String?,
        let type = SCNetworkInterfaceGetInterfaceType(interface)
      else { return nil }
      let kind: ListenerInterfaceKind
      if CFEqual(type, kSCNetworkInterfaceTypeIEEE80211) {
        kind = .wifi
      } else if CFEqual(type, kSCNetworkInterfaceTypeEthernet) {
        kind = .ethernet
      } else if CFEqual(type, kSCNetworkInterfaceTypeWWAN) {
        kind = .cellular
      } else if CFEqual(type, kSCNetworkInterfaceTypeIPSec)
        || CFEqual(type, kSCNetworkInterfaceTypeL2TP)
        || CFEqual(type, kSCNetworkInterfaceTypePPP)
      {
        kind = .vpn
      } else {
        kind = .other
      }
      return (name, kind)
    }
    return pairs.reduce(into: [:]) { result, pair in
      if let existing = result[pair.0], existing != pair.1 {
        result[pair.0] = .other
      } else {
        result[pair.0] = pair.1
      }
    }
  }

  private static func classify(
    name: String,
    flags: Int32,
    configuredKind: ListenerInterfaceKind?
  ) -> ListenerInterfaceKind {
    if flags & IFF_LOOPBACK != 0 { return .loopback }
    if name.hasPrefix("awdl") || name.hasPrefix("llw") { return .peerToPeer }
    if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("gif")
      || name.hasPrefix("stf")
    {
      return .tunnel
    }
    return configuredKind ?? .other
  }

  private static func numericHost(_ address: UnsafePointer<sockaddr>) -> String? {
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    let length: socklen_t =
      address.pointee.sa_family == UInt8(AF_INET)
      ? socklen_t(MemoryLayout<sockaddr_in>.size)
      : socklen_t(MemoryLayout<sockaddr_in6>.size)
    guard getnameinfo(address, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0
    else {
      return nil
    }
    let end = host.firstIndex(of: 0) ?? host.endIndex
    return String(decoding: host[..<end].map(UInt8.init(bitPattern:)), as: UTF8.self)
  }
}

/// Resolves the live `NWInterface` object a binding must be pinned to
/// (ADR §8 "exact live `NWInterface` object pinning", deferred from the
/// spike and owned by this step).
///
/// Returning `nil` means no live object matched. For an eligible production
/// interface that is fatal — startup fails closed rather than binding by
/// address and interface *type* alone. The test-only loopback binding
/// tolerates `nil` and falls back to the required interface type, because
/// `lo0` is not guaranteed to appear in a path's available interfaces.
public protocol ListenerLiveInterfaceResolving: Sendable {
  /// The live interface object whose BSD name equals `bsdName`, or `nil`.
  func resolveLiveInterface(bsdName: String) async -> NWInterface?
}

/// Production resolver backed by `NWPathMonitor`.
///
/// It starts a monitor, takes the first path update (or gives up after a
/// bounded wait), and matches on the BSD interface name. Nothing about the
/// path is logged or returned beyond the matched object.
public struct NWPathMonitorInterfaceResolver: ListenerLiveInterfaceResolving {
  private let timeout: Duration

  /// Creates a resolver with a bounded first-update wait.
  public init(timeout: Duration = .seconds(2)) {
    self.timeout = timeout
  }

  public func resolveLiveInterface(bsdName: String) async -> NWInterface? {
    let monitor = NWPathMonitor()
    let queue = DispatchQueue(label: "com.codexmicro.bridge.listener.path")
    let box = FirstPathBox()
    monitor.pathUpdateHandler = { path in
      box.deliver(path.availableInterfaces.first { $0.name == bsdName })
    }
    monitor.start(queue: queue)
    defer { monitor.cancel() }
    return await box.value(timeout: timeout)
  }
}

/// One-shot delivery box for the first `NWPathMonitor` update. The first
/// caller of ``deliver(_:)`` wins; later updates and the timeout are ignored.
private final class FirstPathBox: @unchecked Sendable {
  private let lock = NSLock()
  private var resolved: NWInterface??
  private var continuation: CheckedContinuation<NWInterface?, Never>?

  func deliver(_ interface: NWInterface?) {
    let waiter: CheckedContinuation<NWInterface?, Never>? = lock.withLock {
      guard resolved == nil else { return nil }
      resolved = .some(interface)
      let waiter = continuation
      continuation = nil
      return waiter
    }
    waiter?.resume(returning: interface)
  }

  func value(timeout: Duration) async -> NWInterface? {
    let timer = Task {
      try? await Task.sleep(for: timeout)
      self.deliver(nil)
    }
    defer { timer.cancel() }
    return await withCheckedContinuation { continuation in
      let settled: NWInterface?? = lock.withLock {
        if let resolved { return resolved }
        self.continuation = continuation
        return nil
      }
      if let settled {
        continuation.resume(returning: settled)
      }
    }
  }
}
