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

/// Evidence that the Mac user asked for LAN access during this process.
///
/// The listener is off by default and nothing persists an enablement, so a
/// restarted bridge always comes up disabled (plan §2 invariant 2, §7
/// gate 1). Until Step 2.14 the *only* enabled configuration came from
/// ``ListenerConfiguration/testOnlyEnabled(binding:interfacePolicy:ceilings:handshake:logger:now:)``,
/// which meant the shipping app had no route to a bound socket at all.
///
/// This type closes that gap without weakening the default. An enabled
/// configuration cannot be spelled by accident because it requires a value
/// only ``userRequested()`` produces: the type has no public initializer, no
/// `Codable` conformance, and no stored state, so it cannot be decoded from
/// a preference, restored from disk, or forged by a caller that merely
/// wants the listener up.
public struct ListenerEnablement: Sendable {
  /// Minted by the LAN control when the user turns LAN access on.
  ///
  /// Call sites are auditable precisely because this is the only way to
  /// make one: grep for `userRequested` and every production enable is in
  /// front of you.
  public static func userRequested() -> ListenerEnablement { ListenerEnablement() }

  private init() {}
}

/// Listener configuration.
///
/// The listener is **off by default** (plan §2 invariant 2, §7 gate 1).
/// Two factories produce an enabled configuration and no others exist:
/// ``enabled(by:binding:interfacePolicy:ceilings:handshake:logger:now:)``,
/// which demands a ``ListenerEnablement`` the user's own action minted, and
/// ``testOnlyEnabled(binding:interfacePolicy:ceilings:handshake:logger:now:)``
/// for deterministic and loopback tests.
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
  /// The scoped-observation seam (Step 2.8).
  ///
  /// Defaults to the denying handler on every factory, so a listener built
  /// without one serves nothing rather than serving unfiltered state.
  public let observation: any ListenerObservationHandling
  /// The command seam (Step 2.9). Denying by default, for the same reason.
  public let commands: any ListenerCommandHandling
  /// Where an authenticated connection claims its directional codecs.
  ///
  /// This must be the *same* registry the handshake handler writes into —
  /// ``CoordinatorListenerHandshakeHandler/frameRegistry`` — or an
  /// authenticated connection finds no codecs and can open no application
  /// message.
  public let frameProvider: any ListenerSessionFrameProviding
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
      observation: DenyingListenerObservationHandler(),
      commands: DenyingListenerCommandHandler(),
      frameProvider: DenyingListenerSessionFrameProvider(),
      logger: DiscardingListenerLogger(),
      now: ListenerMonotonicClock.system
    )
  }

  /// The production enabled configuration.
  ///
  /// `enablement` is unused as a value and that is deliberate: it exists to
  /// make the *type* of this call site unforgeable. Requiring it means an
  /// enabled listener can only be built where a user action was taken, and
  /// the compiler enforces that rather than a comment.
  ///
  /// The interface policy defaults to the strict one — loopback is refused,
  /// so a production bridge binds a real LAN interface or nothing.
  public static func enabled(
    by enablement: ListenerEnablement,
    binding: ListenerInterfaceBinding,
    interfacePolicy: ListenerInterfacePolicy = ListenerInterfacePolicy(),
    ceilings: ListenerCeilings = ListenerCeilings(),
    handshake: any ListenerHandshakeHandling,
    observation: any ListenerObservationHandling = DenyingListenerObservationHandler(),
    commands: any ListenerCommandHandling = DenyingListenerCommandHandler(),
    frameProvider: any ListenerSessionFrameProviding = DenyingListenerSessionFrameProvider(),
    logger: any ListenerLogging = DiscardingListenerLogger(),
    now: @escaping @Sendable () -> UInt64 = ListenerMonotonicClock.system
  ) -> ListenerConfiguration {
    _ = enablement
    return ListenerConfiguration(
      isEnabled: true,
      binding: binding,
      interfacePolicy: interfacePolicy,
      ceilings: ceilings,
      handshake: handshake,
      observation: observation,
      commands: commands,
      frameProvider: frameProvider,
      logger: logger,
      now: now
    )
  }

  /// The test-only enabled configuration, which defaults to permitting a
  /// loopback bind so deterministic tests need no LAN.
  public static func testOnlyEnabled(
    binding: ListenerInterfaceBinding,
    interfacePolicy: ListenerInterfacePolicy = ListenerInterfacePolicy(allowLoopbackForTests: true),
    ceilings: ListenerCeilings = ListenerCeilings(),
    handshake: any ListenerHandshakeHandling = DenyingListenerHandshakeHandler(),
    observation: any ListenerObservationHandling = DenyingListenerObservationHandler(),
    commands: any ListenerCommandHandling = DenyingListenerCommandHandler(),
    frameProvider: any ListenerSessionFrameProviding = DenyingListenerSessionFrameProvider(),
    logger: any ListenerLogging = DiscardingListenerLogger(),
    now: @escaping @Sendable () -> UInt64 = ListenerMonotonicClock.system
  ) -> ListenerConfiguration {
    ListenerConfiguration(
      isEnabled: true,
      binding: binding,
      interfacePolicy: interfacePolicy,
      ceilings: ceilings,
      handshake: handshake,
      observation: observation,
      commands: commands,
      frameProvider: frameProvider,
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
    observation: any ListenerObservationHandling,
    commands: any ListenerCommandHandling,
    frameProvider: any ListenerSessionFrameProviding,
    logger: any ListenerLogging,
    now: @escaping @Sendable () -> UInt64
  ) {
    self.isEnabled = isEnabled
    self.binding = binding
    self.interfacePolicy = interfacePolicy
    self.ceilings = ceilings
    self.handshake = handshake
    self.observation = observation
    self.commands = commands
    self.frameProvider = frameProvider
    self.logger = logger
    self.now = now
  }
}
