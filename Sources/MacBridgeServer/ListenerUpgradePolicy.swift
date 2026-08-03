import CompanionProtocol
import Foundation
import NIOHTTP1

/// Closed HTTP-upgrade rejection vocabulary (ADR §9/§13).
///
/// A rejection code exists for diagnostics and tests; it never travels to
/// the peer, which sees only a closed connection. No case carries a header
/// name, header value, URI, or peer-supplied byte.
public enum ListenerUpgradeRejection: String, Error, Equatable, CaseIterable, Sendable {
  /// More header fields than the ceiling allows.
  case headerCount
  /// A header name outside the allowlist, or a required header repeated.
  case headerName
  /// Total header bytes exceeded the ceiling.
  case headerSize
  /// `Host` was missing, empty, or repeated.
  case host
  /// The method was not `GET`.
  case method
  /// `Origin` was absent or not the exact expected value.
  case origin
  /// The request target was not the exact path, or carried a query string.
  case pathOrQuery
  /// `Sec-WebSocket-Protocol` was not exactly the expected subprotocol.
  case protocolToken
  /// A required upgrade header was missing or malformed, including an
  /// invalid `Sec-WebSocket-Key`.
  case requiredHeader
  /// The HTTP version was not 1.1, or `Sec-WebSocket-Version` was not 13.
  case version
  /// A `Sec-WebSocket-Extensions` offer other than the single tolerated
  /// `permessage-deflate` offer was present.
  case websocketExtensions
}

/// Exact HTTP/1.1 upgrade policy for the hardened listener (ADR §9).
///
/// Everything the peer controls before authentication is checked here:
/// method, version, target, header count/size/names, `Host`, `Connection`,
/// `Upgrade`, `Sec-WebSocket-Version`/`-Key`/`-Protocol`/`-Extensions`, and
/// `Origin`. Compression is never negotiated: `URLSessionWebSocketTask`
/// offers `permessage-deflate` with no public suppression switch, so exactly
/// that offer is tolerated, omitted from the response, and RSV bits are
/// rejected at the frame layer.
public struct ListenerUpgradePolicy: Sendable {
  /// The single fixed upgrade path. Any other target, and any query string,
  /// is rejected.
  public static let path = "/codex-micro/bridge/v1"
  /// The exact required `Origin` value.
  public static let origin = "https://codex-micro-bridge.invalid"
  /// The exact required WebSocket subprotocol.
  public static let subprotocol = "codex-micro.bridge.v1"
  /// The only tolerated extension offer; it is never echoed in the response.
  public static let toleratedExtensionOffer = "permessage-deflate"

  /// Lowercased header-name allowlist. A request naming anything else is
  /// rejected before any value is examined.
  static let allowedHeaderNames: Set<String> = [
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "host",
    "origin",
    "pragma",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "upgrade",
    "user-agent",
  ]

  /// Creates the policy. It holds no state and no peer-derived value.
  public init() {}

  /// Evaluates an upgrade request.
  ///
  /// On success the returned headers are exactly the response headers the
  /// upgrade must add — the subprotocol and nothing else, so no extension
  /// is ever negotiated.
  public func evaluate(
    _ request: HTTPRequestHead
  ) -> Result<HTTPHeaders, ListenerUpgradeRejection> {
    guard request.method == .GET else { return .failure(.method) }
    guard request.version == .http1_1 else { return .failure(.version) }
    guard request.uri == Self.path else { return .failure(.pathOrQuery) }
    guard request.headers.count <= SecureTransportLimits.maxHeaderFieldCount else {
      return .failure(.headerCount)
    }

    var totalHeaderBytes = 0
    for header in request.headers {
      let name = header.name.lowercased()
      guard Self.allowedHeaderNames.contains(name) else { return .failure(.headerName) }
      let fieldBytes = name.utf8.count + header.value.utf8.count + 4
      guard fieldBytes <= SecureTransportLimits.maxHeaderFieldBytes else {
        return .failure(.headerSize)
      }
      totalHeaderBytes += fieldBytes
      guard totalHeaderBytes <= SecureTransportLimits.maxHeaderTotalBytes else {
        return .failure(.headerSize)
      }
    }

    guard singleHeader("host", in: request.headers)?.isEmpty == false else {
      return .failure(.host)
    }
    guard singleHeader("upgrade", in: request.headers)?.lowercased() == "websocket" else {
      return .failure(.requiredHeader)
    }
    guard let connection = singleHeader("connection", in: request.headers),
      commaSeparatedTokens(connection).contains("upgrade")
    else {
      return .failure(.requiredHeader)
    }
    guard singleHeader("sec-websocket-version", in: request.headers) == "13" else {
      return .failure(.version)
    }
    guard let key = singleHeader("sec-websocket-key", in: request.headers),
      let decodedKey = Data(base64Encoded: key), decodedKey.count == 16
    else {
      return .failure(.requiredHeader)
    }
    let accepts = request.headers["accept"]
    guard accepts.isEmpty || accepts == ["*/*"] else { return .failure(.requiredHeader) }
    let contentLengths = request.headers["content-length"]
    guard contentLengths.isEmpty || contentLengths == ["0"] else {
      return .failure(.requiredHeader)
    }
    guard singleHeader("origin", in: request.headers) == Self.origin else {
      return .failure(.origin)
    }
    // ADR §9 fixes the subprotocol as an exact single value, so the token is
    // compared case-sensitively. `Connection` and `Upgrade` above stay
    // case-insensitive because RFC 9110 defines those tokens that way.
    guard let requestedProtocol = singleHeader("sec-websocket-protocol", in: request.headers),
      caseSensitiveTokens(requestedProtocol) == [Self.subprotocol]
    else {
      return .failure(.protocolToken)
    }
    let extensionOffers = request.headers[canonicalForm: "Sec-WebSocket-Extensions"].map(
      String.init)
    guard extensionOffers.isEmpty || extensionOffers == [Self.toleratedExtensionOffer] else {
      return .failure(.websocketExtensions)
    }

    var response = HTTPHeaders()
    response.add(name: "Sec-WebSocket-Protocol", value: Self.subprotocol)
    return .success(response)
  }

  /// The single value of `name`, or `nil` when absent or repeated. Every
  /// required header must occur exactly once.
  private func singleHeader(_ name: String, in headers: HTTPHeaders) -> String? {
    let values = headers[name]
    guard values.count == 1 else { return nil }
    return values[0].trimmingCharacters(in: .whitespaces)
  }

  private func commaSeparatedTokens(_ value: String) -> [String] {
    caseSensitiveTokens(value).map { $0.lowercased() }
  }

  private func caseSensitiveTokens(_ value: String) -> [String] {
    value.split(separator: ",", omittingEmptySubsequences: false).map {
      $0.trimmingCharacters(in: .whitespaces)
    }
  }
}
