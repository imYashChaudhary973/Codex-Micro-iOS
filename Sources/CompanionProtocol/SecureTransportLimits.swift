/// Transport constants and wire-field bounds fixed by the Phase 2 transport ADR
/// (§9) and canonical encoding contract (§11).
///
/// Step 2.2 defines these values as named constants only. The WebSocket-level
/// constants are enforced by the hardened listener (Step 2.7); the sealed-frame
/// carriage that transports these messages arrives with Steps 2.3/2.7. The
/// wire-field bounds are enforced today by every strict decoder in this module.
public enum SecureTransportLimits {
  // MARK: - WebSocket framing (ADR §9 proven constants)

  /// Maximum size of a single WebSocket frame in bytes (16 KiB).
  public static let maxFrameBytes = 16 * 1024
  /// Maximum size of a complete WebSocket message in bytes (64 KiB).
  public static let maxMessageBytes = 64 * 1024
  /// Maximum number of fragments a single message may span.
  public static let maxFragmentsPerMessage = 8
  /// Maximum number of HTTP upgrade header fields.
  public static let maxHeaderFieldCount = 16
  /// Maximum total HTTP upgrade header size in bytes (8 KiB).
  public static let maxHeaderTotalBytes = 8 * 1024
  /// Maximum size of a single HTTP upgrade header field in bytes (4 KiB).
  public static let maxHeaderFieldBytes = 4 * 1024

  // MARK: - Deadlines and ceilings (ADR §9, enforced in Step 2.7)

  /// TLS plus HTTP upgrade completion deadline, in seconds from TCP accept.
  public static let upgradeDeadlineSeconds = 10
  /// Authentication handshake deadline, in seconds from upgrade completion.
  public static let authenticationDeadlineSeconds = 20
  /// Global concurrent connection ceiling.
  public static let maxConcurrentConnections = 16
  /// Concurrent unauthenticated connection ceiling.
  public static let maxUnauthenticatedConnections = 4
  /// Per-source new connection ceiling per minute.
  public static let maxNewConnectionsPerSourcePerMinute = 6
  /// Per-source pairing attempt ceiling per minute.
  public static let maxPairingAttemptsPerSourcePerMinute = 3
  /// Per-connection inbound message-rate ceiling per second.
  public static let maxInboundMessagesPerSecond = 32
  /// Per-connection inbound byte-rate ceiling per second (1 MiB).
  public static let maxInboundBytesPerSecond = 1_048_576
  /// Outbound queue ceiling in frames per connection.
  public static let maxOutboundQueueFrames = 64
  /// Outbound queue ceiling in bytes per connection (256 KiB).
  public static let maxOutboundQueueBytes = 256 * 1024
  /// Maximum seconds a connection may remain non-writable before closing.
  public static let maxNonWritableSeconds = 10
  /// Server ping cadence in seconds.
  public static let pingCadenceSeconds = 30
  /// Matching-pong deadline in seconds.
  public static let pongDeadlineSeconds = 10
  /// Post-upgrade application idle expiry in seconds.
  public static let idleExpirySeconds = 120

  // MARK: - Wire-field bounds (Step 2.2 schema, enforced by strict decoders)

  /// Exact byte count of every pairing/session nonce (256 bits).
  public static let nonceByteCount = 32
  /// Exact byte count of the single-use pairing bootstrap secret (256 bits).
  public static let bootstrapSecretByteCount = 32
  /// Exact byte count of a raw `r||s` P-256 signature (ADR §11).
  public static let signatureByteCount = 64
  /// Exact byte count of an X9.63 uncompressed P-256 public key.
  public static let publicKeyByteCount = 65
  /// Exact byte count of the 128-bit journal epoch.
  public static let journalEpochByteCount = 16
  /// Maximum UTF-8 byte count of a normalized direct-LAN endpoint origin.
  public static let maxEndpointOriginBytes = 128
  /// Maximum byte count of one observation delivery payload. Sized so the
  /// base64/JSON expansion stays inside `maxMessageBytes` after sealing.
  public static let maxObservationPayloadBytes = 32 * 1024
  /// Maximum number of features in one protocol selection.
  public static let maxFeatureCount = SecureProtocolFeature.allCases.count
}
