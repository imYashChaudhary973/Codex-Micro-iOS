import Darwin
import Foundation
import NIOCore
import SystemConfiguration

public enum NetworkInterfaceKind: String, CaseIterable, Sendable {
  case wifi
  case ethernet
  case loopback
  case vpn
  case tunnel
  case cellular
  case peerToPeer
  case other
  case wildcard
}

public struct NetworkInterfaceDescriptor: Equatable, Sendable {
  public let identifier: String
  public let kind: NetworkInterfaceKind
  public let isUp: Bool
  public let isRunning: Bool
  public let isPointToPoint: Bool
}

public struct InterfacePolicy: Sendable {
  public let allowLoopbackForTests: Bool

  public init(allowLoopbackForTests: Bool = false) {
    self.allowLoopbackForTests = allowLoopbackForTests
  }

  public func allows(_ interface: NetworkInterfaceDescriptor) -> Bool {
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

public enum InterfaceBindingError: Error, Equatable {
  case addressDenied
  case interfaceDenied
  case nonNumericAddress
}

public struct InterfaceBinding: Equatable, Sendable {
  public let interface: NetworkInterfaceDescriptor
  public let host: String
  public let socketAddress: SocketAddress

  private init(
    interface: NetworkInterfaceDescriptor,
    host: String,
    socketAddress: SocketAddress
  ) {
    self.interface = interface
    self.host = host
    self.socketAddress = socketAddress
  }

  static func validated(
    interface: NetworkInterfaceDescriptor,
    numericAddress: String,
    policy: InterfacePolicy
  ) throws -> InterfaceBinding {
    guard policy.allows(interface) else { throw InterfaceBindingError.interfaceDenied }
    guard LocalAddressPolicy.isNumeric(numericAddress) else {
      throw InterfaceBindingError.nonNumericAddress
    }
    guard
      LocalAddressPolicy.allows(
        numericAddress,
        interfaceKind: interface.kind,
        allowLoopbackForTests: policy.allowLoopbackForTests
      )
    else {
      throw InterfaceBindingError.addressDenied
    }
    let socketAddress: SocketAddress
    do {
      socketAddress = try SocketAddress(ipAddress: numericAddress, port: 0)
    } catch {
      throw InterfaceBindingError.nonNumericAddress
    }
    return InterfaceBinding(
      interface: interface,
      host: numericAddress,
      socketAddress: socketAddress
    )
  }

  public static func testOnlyLoopback() throws -> InterfaceBinding {
    try validated(
      interface: NetworkInterfaceDescriptor(
        identifier: "test-loopback",
        kind: .loopback,
        isUp: true,
        isRunning: true,
        isPointToPoint: false
      ),
      numericAddress: "127.0.0.1",
      policy: InterfacePolicy(allowLoopbackForTests: true)
    )
  }

  public func revalidated(policy: InterfacePolicy) throws -> SocketAddress {
    try Self.validated(interface: interface, numericAddress: host, policy: policy).socketAddress
  }
}

private enum LocalAddressPolicy {
  static func isNumeric(_ address: String) -> Bool {
    var ipv4 = in_addr()
    if inet_pton(AF_INET, address, &ipv4) == 1 { return true }
    var ipv6 = in6_addr()
    return inet_pton(AF_INET6, address, &ipv6) == 1
  }

  static func allows(
    _ address: String,
    interfaceKind: NetworkInterfaceKind,
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

public enum InterfaceDiscoveryError: Error, Equatable {
  case enumerationFailed(Int32)
  case noEligibleBinding
}

public enum InterfaceDiscovery {
  public static func eligibleBindings(policy: InterfacePolicy) throws -> [InterfaceBinding] {
    let typeByName = configuredInterfaceKinds()
    var pointer: UnsafeMutablePointer<ifaddrs>?
    let status = getifaddrs(&pointer)
    guard status == 0, let first = pointer else {
      throw InterfaceDiscoveryError.enumerationFailed(errno)
    }
    defer { freeifaddrs(first) }

    var results: [InterfaceBinding] = []
    var current: UnsafeMutablePointer<ifaddrs>? = first
    while let entry = current?.pointee {
      defer { current = entry.ifa_next }
      guard let address = entry.ifa_addr else { continue }
      let family = Int32(address.pointee.sa_family)
      guard family == AF_INET || family == AF_INET6 else { continue }

      let name = String(cString: entry.ifa_name)
      let flags = Int32(entry.ifa_flags)
      let descriptor = NetworkInterfaceDescriptor(
        identifier: name,
        kind: classify(name: name, flags: flags, configuredKind: typeByName[name]),
        isUp: flags & IFF_UP != 0,
        isRunning: flags & IFF_RUNNING != 0,
        isPointToPoint: flags & IFF_POINTOPOINT != 0
      )
      guard let host = numericHost(address),
        let binding = try? InterfaceBinding.validated(
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

  public static func firstEligibleBinding(policy: InterfacePolicy) throws -> InterfaceBinding {
    guard let binding = try eligibleBindings(policy: policy).first else {
      throw InterfaceDiscoveryError.noEligibleBinding
    }
    return binding
  }

  private static func configuredInterfaceKinds() -> [String: NetworkInterfaceKind] {
    guard let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [:] }
    let pairs: [(String, NetworkInterfaceKind)] = interfaces.compactMap {
      interface -> (String, NetworkInterfaceKind)? in
      guard let name = SCNetworkInterfaceGetBSDName(interface) as String?,
        let type = SCNetworkInterfaceGetInterfaceType(interface)
      else { return nil }
      let kind: NetworkInterfaceKind
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
    configuredKind: NetworkInterfaceKind?
  ) -> NetworkInterfaceKind {
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
