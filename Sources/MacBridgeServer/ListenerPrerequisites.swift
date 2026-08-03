import Foundation
import Security

/// The TLS material the listener serves.
///
/// The production value comes from ``BridgeTLSIdentityAssembly/makeSecIdentity(material:identity:)``,
/// which requires the Secure Enclave `.tls` identity, so the served private
/// key is non-exportable by construction (ADR §6). The fingerprint is the
/// SPKI digest clients pin; certificate bytes are never pinned, so same-key
/// renewal is transparent (ADR §7).
public struct ListenerServingIdentity: @unchecked Sendable {
  /// The platform identity Network.framework TLS signs with.
  public let secIdentity: SecIdentity
  /// The SHA-256 SPKI fingerprint clients pin.
  public let spkiFingerprint: Data

  /// Assembles the serving identity from an issued certificate and the
  /// Secure Enclave `.tls` identity. This is the only production path.
  public init(certificate: BridgeTLSCertificate, identity: BridgeIdentity) throws {
    self.secIdentity = try BridgeTLSIdentityAssembly.makeSecIdentity(
      material: certificate,
      identity: identity
    )
    self.spkiFingerprint = certificate.spkiFingerprint
  }

  /// Wraps an already-assembled identity.
  ///
  /// Deterministic tests and the Step 2.14 acceptance tooling use this with
  /// an ephemeral non-persistent key, because a Secure Enclave key needs an
  /// entitled signed host. Production startup uses ``init(certificate:identity:)``,
  /// whose assembly refuses anything that is not Secure Enclave-backed.
  public static func testOnlyAssembled(
    secIdentity: SecIdentity,
    spkiFingerprint: Data
  ) -> ListenerServingIdentity {
    ListenerServingIdentity(secIdentity: secIdentity, spkiFingerprint: spkiFingerprint)
  }

  private init(secIdentity: SecIdentity, spkiFingerprint: Data) {
    self.secIdentity = secIdentity
    self.spkiFingerprint = spkiFingerprint
  }
}

/// Supplies the serving TLS identity, or fails the listener closed.
///
/// Throwing — including for a missing, duplicate, exportable, or
/// SPKI-mismatched identity — disables LAN. There is no degraded or
/// unauthenticated mode (plan §2 invariant 2).
public protocol ListenerTLSIdentityProviding: Sendable {
  /// The identity to serve, or a throw that disables LAN.
  func servingIdentity() async throws -> ListenerServingIdentity
}

/// Confirms the Mac-authoritative device-grant authority is readable and
/// current before the listener binds.
///
/// A missing, duplicate, undecodable, oversized, or rolled-back authority
/// blob disables LAN entirely (ADR §10, plan §2 invariant 2). The real
/// implementation lives in `MacBridgeCore`; the listener sees only this
/// probe, which is why `MacBridgeServer` owns no grant state.
public protocol ListenerGrantAuthorityProbing: Sendable {
  /// Throws when the grant authority is unavailable.
  func assertGrantAuthorityAvailable() async throws
}

/// Confirms the authorization policy is available before the listener binds.
public protocol ListenerPolicyProbing: Sendable {
  /// Throws when the authorization policy is unavailable.
  func assertPolicyAvailable() async throws
}

/// Confirms the installed Codex is supported before the listener binds.
///
/// Codex being unsupported disables the listener outright; it is not a
/// degraded mode (plan §2 invariant 2). The listener never reaches a Codex
/// executor — that path belongs to the Step 2.9 gateway — so this is a
/// yes/no probe and nothing more.
public protocol ListenerCodexSupportProbing: Sendable {
  /// Throws when the installed Codex is unsupported.
  func assertCodexSupported() async throws
}

/// The complete startup prerequisite set. Each probe is independent and any
/// one failure disables LAN.
public struct ListenerPrerequisites: Sendable {
  /// TLS identity source.
  public let identity: any ListenerTLSIdentityProviding
  /// Grant-authority availability probe.
  public let grantAuthority: any ListenerGrantAuthorityProbing
  /// Authorization-policy availability probe.
  public let policy: any ListenerPolicyProbing
  /// Codex support probe.
  public let codex: any ListenerCodexSupportProbing
  /// Live `NWInterface` object resolver (ADR §8).
  public let liveInterface: any ListenerLiveInterfaceResolving

  /// Creates the prerequisite set.
  public init(
    identity: any ListenerTLSIdentityProviding,
    grantAuthority: any ListenerGrantAuthorityProbing,
    policy: any ListenerPolicyProbing,
    codex: any ListenerCodexSupportProbing,
    liveInterface: any ListenerLiveInterfaceResolving = NWPathMonitorInterfaceResolver()
  ) {
    self.identity = identity
    self.grantAuthority = grantAuthority
    self.policy = policy
    self.codex = codex
    self.liveInterface = liveInterface
  }

  /// Runs every probe in a fixed order and returns the serving identity.
  ///
  /// The order is deliberate and stable: enablement, then Codex support,
  /// then policy, then grant authority, then identity. Each throws its own
  /// ``ListenerStartupFailure``, so a test can prove each prerequisite
  /// independently.
  func resolve(isEnabled: Bool) async throws -> ListenerServingIdentity {
    guard isEnabled else { throw ListenerStartupFailure.notEnabled }
    do {
      try await codex.assertCodexSupported()
    } catch {
      throw ListenerStartupFailure.codexUnsupported
    }
    do {
      try await policy.assertPolicyAvailable()
    } catch {
      throw ListenerStartupFailure.policyUnavailable
    }
    do {
      try await grantAuthority.assertGrantAuthorityAvailable()
    } catch {
      throw ListenerStartupFailure.grantAuthorityUnavailable
    }
    do {
      return try await identity.servingIdentity()
    } catch {
      throw ListenerStartupFailure.identityUnavailable
    }
  }
}

/// Listener configuration.
///
/// The listener is **off by default** (plan §2 invariant 2, §7 gate 1).
/// ``testOnlyEnabled(binding:ceilings:handshake:logger:now:)`` is the only
/// factory that produces an enabled configuration, and it exists solely for
/// deterministic and loopback tests. No user-facing enable control exists in
/// this step; Step 2.13 owns it.
public struct ListenerConfiguration: Sendable {
  /// Whether the listener may bind at all.
  public let isEnabled: Bool
  /// The validated bind target.
  public let binding: ListenerInterfaceBinding
  /// Interface eligibility policy, revalidated at startup.
  public let interfacePolicy: ListenerInterfacePolicy
  /// Resource ceilings, validated against ADR §9 at startup.
  public let ceilings: ListenerCeilings
  /// The pairing/authentication seam.
  public let handshake: any ListenerHandshakeHandling
  /// Closed-code logger.
  public let logger: any ListenerLogging
  /// Monotonic nanosecond seam for every rate window.
  public let now: @Sendable () -> UInt64

  /// The default disabled configuration for a discovered binding. A
  /// listener created from it always fails closed with
  /// ``ListenerStartupFailure/notEnabled``.
  public static func disabled(binding: ListenerInterfaceBinding) -> ListenerConfiguration {
    ListenerConfiguration(
      isEnabled: false,
      binding: binding,
      interfacePolicy: ListenerInterfacePolicy(),
      ceilings: ListenerCeilings(),
      handshake: DenyingListenerHandshakeHandler(),
      logger: DiscardingListenerLogger(),
      now: ListenerMonotonicClock.system
    )
  }

  /// The only enabled configuration factory. Internal test configuration
  /// only; there is no user-accessible path to it in Step 2.7.
  public static func testOnlyEnabled(
    binding: ListenerInterfaceBinding,
    interfacePolicy: ListenerInterfacePolicy = ListenerInterfacePolicy(allowLoopbackForTests: true),
    ceilings: ListenerCeilings = ListenerCeilings(),
    handshake: any ListenerHandshakeHandling = DenyingListenerHandshakeHandler(),
    logger: any ListenerLogging = DiscardingListenerLogger(),
    now: @escaping @Sendable () -> UInt64 = ListenerMonotonicClock.system
  ) -> ListenerConfiguration {
    ListenerConfiguration(
      isEnabled: true,
      binding: binding,
      interfacePolicy: interfacePolicy,
      ceilings: ceilings,
      handshake: handshake,
      logger: logger,
      now: now
    )
  }

  private init(
    isEnabled: Bool,
    binding: ListenerInterfaceBinding,
    interfacePolicy: ListenerInterfacePolicy,
    ceilings: ListenerCeilings,
    handshake: any ListenerHandshakeHandling,
    logger: any ListenerLogging,
    now: @escaping @Sendable () -> UInt64
  ) {
    self.isEnabled = isEnabled
    self.binding = binding
    self.interfacePolicy = interfacePolicy
    self.ceilings = ceilings
    self.handshake = handshake
    self.logger = logger
    self.now = now
  }
}
