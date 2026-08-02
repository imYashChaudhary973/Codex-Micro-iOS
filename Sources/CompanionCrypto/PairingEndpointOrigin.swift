import CompanionProtocol
import Foundation

/// Closed rejection vocabulary for direct-LAN endpoint-origin normalization.
/// Every case is a compile-time constant and carries no input content.
public enum PairingEndpointOriginError: Error, Equatable, CaseIterable, Sendable {
  /// The origin is empty, oversized, or contains non-printable-ASCII bytes.
  case malformedOrigin
  /// The scheme is absent or is not the single supported direct-LAN scheme.
  case unsupportedScheme
  /// The authority carries a path, query, fragment, userinfo, or zone ID.
  case unsupportedComponent
  /// The host is not a numeric IPv4 or bracketed IPv6 literal.
  case hostNotNumericAddress
  /// The host is the unspecified (wildcard) address.
  case wildcardAddress
  /// The host is an IPv4-mapped IPv6 address, which aliases an IPv4 origin.
  case aliasedAddress
  /// The port is absent after its separator, non-numeric, or out of range.
  case invalidPort
}

/// A normalized direct-LAN endpoint origin (ADR §8/§12).
///
/// Pairing compares endpoints by **normalized equality only**: the QR-carried
/// origin, the origin the device echoes in its pairing request, and the
/// origin bound into the canonical pairing transcript must all normalize to
/// the same bytes. Normalization is total and deterministic:
///
/// - the scheme is lowercased and must be exactly `wss`;
/// - the host must be a numeric address — IPv4 in strict dotted-quad form or
///   IPv6 inside brackets, rendered in RFC 5952 canonical form (lowercase,
///   no leading zeros, longest zero run compressed);
/// - the default port (443) is elided and any other port is kept verbatim;
/// - hostnames, wildcard addresses, IPv4-mapped IPv6 addresses, userinfo,
///   zone IDs, paths, queries, and fragments are rejected.
///
/// Interface eligibility (private IPv4 / IPv6 ULA on Wi-Fi or Ethernet) stays
/// with the listener's binding policy in `MacBridgeServer`; this type only
/// guarantees an unambiguous, comparable origin string.
public struct PairingEndpointOrigin: Equatable, Hashable, Sendable {
  /// The only direct-LAN scheme Phase 2 speaks.
  public static let scheme = "wss"
  /// The scheme's default port, elided from the normalized form.
  public static let defaultPort: UInt16 = 443

  /// The canonical normalized origin, for example `wss://192.168.4.20:8443`.
  public let normalized: String

  /// Normalizes a raw origin, failing closed on anything ambiguous.
  public init(_ raw: String) throws {
    normalized = try PairingEndpointOriginNormalizer.normalize(raw)
  }
}

/// Pure normalization routine behind ``PairingEndpointOrigin``.
enum PairingEndpointOriginNormalizer {
  static func normalize(_ raw: String) throws -> String {
    guard !raw.isEmpty, raw.utf8.count <= SecureTransportLimits.maxEndpointOriginBytes,
      raw.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value <= 0x7E })
    else {
      throw PairingEndpointOriginError.malformedOrigin
    }
    guard let separator = raw.range(of: "://") else {
      throw PairingEndpointOriginError.unsupportedScheme
    }
    guard raw[raw.startIndex..<separator.lowerBound].lowercased() == PairingEndpointOrigin.scheme
    else {
      throw PairingEndpointOriginError.unsupportedScheme
    }
    let authority = String(raw[separator.upperBound...])
    guard !authority.isEmpty,
      !authority.contains(where: { $0 == "/" || $0 == "?" || $0 == "#" || $0 == "@" })
    else {
      throw PairingEndpointOriginError.unsupportedComponent
    }
    let parsed = try splitAuthority(authority)
    let port = try parsePort(parsed.port)
    let canonicalHost = try canonicalizeHost(parsed.host, bracketed: parsed.bracketed)
    guard let port, port != PairingEndpointOrigin.defaultPort else {
      return "\(PairingEndpointOrigin.scheme)://\(canonicalHost)"
    }
    return "\(PairingEndpointOrigin.scheme)://\(canonicalHost):\(port)"
  }

  private static func splitAuthority(
    _ authority: String
  ) throws -> (host: String, port: String?, bracketed: Bool) {
    guard authority.hasPrefix("[") else {
      guard !authority.contains("]") else {
        throw PairingEndpointOriginError.hostNotNumericAddress
      }
      let parts = authority.split(separator: ":", omittingEmptySubsequences: false)
      switch parts.count {
      case 1: return (String(parts[0]), nil, false)
      case 2: return (String(parts[0]), String(parts[1]), false)
      default: throw PairingEndpointOriginError.hostNotNumericAddress
      }
    }
    guard let close = authority.firstIndex(of: "]") else {
      throw PairingEndpointOriginError.hostNotNumericAddress
    }
    let inner = String(authority[authority.index(after: authority.startIndex)..<close])
    let remainder = String(authority[authority.index(after: close)...])
    if remainder.isEmpty {
      return (inner, nil, true)
    }
    guard remainder.hasPrefix(":") else {
      throw PairingEndpointOriginError.unsupportedComponent
    }
    return (inner, String(remainder.dropFirst()), true)
  }

  private static func parsePort(_ text: String?) throws -> UInt16? {
    guard let text else { return nil }
    guard !text.isEmpty, text.count <= 5, text.allSatisfy(\.isASCII), text.allSatisfy(\.isNumber),
      text.first != "0", let value = UInt16(text), value >= 1
    else {
      throw PairingEndpointOriginError.invalidPort
    }
    return value
  }

  /// Bracketed hosts must be IPv6 and unbracketed hosts must be IPv4, so no
  /// address is expressible in two bracketing forms.
  private static func canonicalizeHost(_ host: String, bracketed: Bool) throws -> String {
    if bracketed {
      let address = try parseIPv6(host)
      guard address.contains(where: { $0 != 0 }) else {
        throw PairingEndpointOriginError.wildcardAddress
      }
      guard !isIPv4Mapped(address) else {
        throw PairingEndpointOriginError.aliasedAddress
      }
      return "[\(renderIPv6(address))]"
    }
    let address = try parseIPv4(host)
    guard address.contains(where: { $0 != 0 }) else {
      throw PairingEndpointOriginError.wildcardAddress
    }
    return address.map(String.init).joined(separator: ".")
  }

  // MARK: - Numeric address parsing

  /// Strict dotted-quad IPv4: exactly four decimal octets, no leading zeros,
  /// no shorthand forms, no hexadecimal or octal notation.
  static func parseIPv4(_ text: String) throws -> [UInt8] {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else {
      throw PairingEndpointOriginError.hostNotNumericAddress
    }
    return try parts.map { part in
      guard !part.isEmpty, part.count <= 3, part.allSatisfy({ $0.isASCII && $0.isNumber }),
        part.count == 1 || part.first != "0", let value = UInt8(part)
      else {
        throw PairingEndpointOriginError.hostNotNumericAddress
      }
      return value
    }
  }

  /// Strict IPv6 text form: at most one `::` run, one to four hex digits per
  /// group, exactly eight groups after expansion. Embedded IPv4 notation and
  /// zone identifiers are rejected so no address has two textual spellings.
  static func parseIPv6(_ text: String) throws -> [UInt8] {
    guard !text.isEmpty, !text.contains("%"), !text.contains(".") else {
      throw PairingEndpointOriginError.hostNotNumericAddress
    }
    let runs = text.components(separatedBy: "::")
    guard runs.count <= 2 else {
      throw PairingEndpointOriginError.hostNotNumericAddress
    }
    let headGroups = try parseGroups(runs[0])
    let tailGroups = runs.count == 2 ? try parseGroups(runs[1]) : []
    var groups: [UInt16]
    if runs.count == 2 {
      let zeros = 8 - headGroups.count - tailGroups.count
      guard zeros >= 1 else {
        throw PairingEndpointOriginError.hostNotNumericAddress
      }
      groups = headGroups + Array(repeating: 0, count: zeros) + tailGroups
    } else {
      groups = headGroups
    }
    guard groups.count == 8 else {
      throw PairingEndpointOriginError.hostNotNumericAddress
    }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(16)
    for group in groups {
      bytes.append(UInt8(truncatingIfNeeded: group >> 8))
      bytes.append(UInt8(truncatingIfNeeded: group))
    }
    return bytes
  }

  private static func parseGroups(_ text: String) throws -> [UInt16] {
    guard !text.isEmpty else { return [] }
    let parts = text.split(separator: ":", omittingEmptySubsequences: false)
    return try parts.map { part in
      guard !part.isEmpty, part.count <= 4,
        part.allSatisfy({ $0.isASCII && $0.isHexDigit }),
        let value = UInt16(part, radix: 16)
      else {
        throw PairingEndpointOriginError.hostNotNumericAddress
      }
      return value
    }
  }

  private static func isIPv4Mapped(_ address: [UInt8]) -> Bool {
    address.prefix(10).allSatisfy { $0 == 0 } && address[10] == 0xFF && address[11] == 0xFF
  }

  /// RFC 5952 canonical rendering: lowercase hex, no leading zeros, and the
  /// longest run of two or more zero groups (leftmost on a tie) compressed.
  static func renderIPv6(_ address: [UInt8]) -> String {
    var groups: [UInt16] = []
    groups.reserveCapacity(8)
    for index in stride(from: 0, to: 16, by: 2) {
      groups.append((UInt16(address[index]) << 8) | UInt16(address[index + 1]))
    }
    var bestStart = -1
    var bestLength = 0
    var runStart = -1
    var runLength = 0
    for (index, group) in groups.enumerated() {
      if group == 0 {
        if runStart < 0 { runStart = index }
        runLength += 1
        if runLength > bestLength {
          bestStart = runStart
          bestLength = runLength
        }
      } else {
        runStart = -1
        runLength = 0
      }
    }
    let rendered = groups.map { String($0, radix: 16, uppercase: false) }
    guard bestLength >= 2 else {
      return rendered.joined(separator: ":")
    }
    let head = rendered[0..<bestStart].joined(separator: ":")
    let tail = rendered[(bestStart + bestLength)...].joined(separator: ":")
    return "\(head)::\(tail)"
  }
}
