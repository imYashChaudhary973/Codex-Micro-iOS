import CompanionCrypto
import CompanionProtocol
import Foundation
import MacBridgeCore
import MacBridgeServer

/// The composition root: the one place a **real** listener is built over the
/// real authority, coordinators, broker, and gateway.
///
/// Every previous step assembled its own piece and proved it against a seam.
/// Nothing constructed the whole graph, and that absence hid a defect the
/// unit tests could not see: ``HardenedWSSListener`` accepted no observation
/// or command handler at all, so the Step 2.8 and 2.9 handlers were reachable
/// only from `ListenerPipeline` in tests. A listener built the production way
/// served the *denying* handlers. Adding those three seams to
/// ``ListenerConfiguration`` is what makes this file possible, and this file
/// is what would have caught it.
///
/// The assembly owns no policy. It decides only what is connected to what,
/// and every decision it makes is a wiring decision.

// MARK: - The listener as a LAN-controllable resource

/// The hardened listener already has exactly the shape the LAN control needs.
///
/// The conformance is stated rather than adapted because the semantics match:
/// `start()` binds and returns the endpoint, `stop()` joins teardown, and the
/// lifecycle is one-shot, which is precisely what
/// ``BridgeListenerControlling`` documents its callers must assume.
extension HardenedWSSListener: BridgeListenerControlling {}

// MARK: - TLS identity

/// Serves the LAN listener's TLS identity from the Secure Enclave `.tls` key.
///
/// The private key never leaves the Enclave: the certificate is signed
/// through the identity backend and the served `SecIdentity` is assembled by
/// ``BridgeTLSIdentityAssembly``, which refuses anything not Enclave-backed
/// (ADR §6). Clients pin the SPKI fingerprint, never certificate bytes, so
/// same-key renewal below is invisible to a paired phone (ADR §7).
///
/// **A lost identity is not silently replaced.** Once a certificate has been
/// issued, the SPKI it pinned becomes the expectation for every later load;
/// an identity that then goes missing surfaces `identityLost` rather than a
/// fresh key, which disables LAN and requires an explicit reset plus
/// re-pairing. Any other outcome would let a wiped keychain silently
/// invalidate every phone's pin while the bridge kept claiming to be itself.
public actor BridgeSecureEnclaveTLSProvider: ListenerTLSIdentityProviding {
  /// Built inside the actor rather than handed in: `BridgeIdentityStore` is
  /// not `Sendable` (it holds a backend and a policy closure), so passing one
  /// across the isolation boundary would be exactly the data race the compiler
  /// flags. The factory keeps the store confined to this actor for its whole
  /// life.
  private let makeStore: @Sendable () -> BridgeIdentityStore
  private lazy var store: BridgeIdentityStore = makeStore()
  private let rotation: TLSRotationAuthority?
  private let currentDate: @Sendable () -> Date
  private var issued: BridgeTLSCertificate?
  private var pinnedSPKI: Data?

  /// Creates the provider.
  ///
  /// - Parameters:
  ///   - makeStore: Builds the identity store over the Secure Enclave
  ///     backend, inside this actor.
  ///   - rotation: The anti-rollback rotation authority, when one is
  ///     available. The generation-0 baseline is recorded the first time a
  ///     certificate is issued; a baseline that already exists is left
  ///     alone, never overwritten.
  ///   - currentDate: Wall-clock seam, injected so renewal is testable.
  public init(
    makeStore: @escaping @Sendable () -> BridgeIdentityStore,
    rotation: TLSRotationAuthority? = nil,
    currentDate: @escaping @Sendable () -> Date = { Date() }
  ) {
    self.makeStore = makeStore
    self.rotation = rotation
    self.currentDate = currentDate
  }

  public func servingIdentity() async throws -> ListenerServingIdentity {
    let now = currentDate()
    // Once anything has been pinned, demand it. This is the load that turns
    // a wiped Enclave into a refusal instead of a new key.
    let identity = try store.loadOrCreate(
      role: .tls,
      expectedSPKIFingerprint: pinnedSPKI
    ).identity

    let certificate: BridgeTLSCertificate
    if let existing = issued, !BridgeCertificateFactory.isRenewalDue(for: existing, at: now) {
      certificate = existing
    } else if let existing = issued {
      certificate = try BridgeCertificateFactory.renew(
        existing, identity: identity, currentDate: now)
    } else {
      certificate = try BridgeCertificateFactory.makeSelfSigned(
        identity: identity, currentDate: now)
      // First issuance records the anti-rollback baseline. A pre-existing
      // baseline belongs to an earlier run of this same key and must survive.
      _ = try? rotation?.initializeBaseline(
        currentSPKIFingerprint: certificate.spkiFingerprint)
    }

    issued = certificate
    pinnedSPKI = certificate.spkiFingerprint
    return try ListenerServingIdentity(certificate: certificate, identity: identity)
  }

  /// The fingerprint currently served, or `nil` before the first issuance.
  /// The pairing QR carries this, so it is read, never guessed.
  public var servedSPKIFingerprint: Data? { pinnedSPKI }
}

// MARK: - Startup probes

/// Refuses the bind when the Mac-authoritative grant authority is not
/// readable and current.
///
/// The authority latches closed on a corrupt, duplicate, oversized, or
/// rolled-back blob and stays that way; a latched authority must take LAN
/// down with it rather than let the listener bind into a state where every
/// authorization read would fail (ADR §10, plan §2 invariant 2).
public struct BridgeGrantAuthorityProbe: ListenerGrantAuthorityProbing {
  private let authority: DeviceGrantAuthority

  public init(authority: DeviceGrantAuthority) {
    self.authority = authority
  }

  public func assertGrantAuthorityAvailable() async throws {
    switch await authority.availability() {
    case .available: return
    case .unavailable(let error): throw error
    }
  }
}

/// Refuses the bind when the capability policy's fail-closed floor is wrong.
///
/// The policy is compiled in rather than stored, so there is no file to find
/// missing. What there *is* to check is the property the whole authorization
/// path leans on: `authorize` combines the grant's profile with the host's
/// through ``MobileActionProfile/mostRestrictive(_:)`` and refuses agent work
/// unless the result permits it. Combining *every* profile must therefore
/// land on `observe`, the floor. A profile added later in the wrong lattice
/// position would move that floor and silently widen every device at once,
/// so it is worth one comparison at startup.
///
/// `permitsAgentWork` is deliberately not consulted here — it is fileprivate
/// to the policy, and widening it to let a probe read it would trade a real
/// encapsulation boundary for a test convenience.
public struct BridgeCapabilityPolicyProbe: ListenerPolicyProbing {
  /// Raised when the profile lattice does not fail closed.
  public enum Failure: Error, Equatable, Sendable {
    case profileTableEmpty
    case latticeFloorMoved(MobileActionProfile)
  }

  public init() {}

  public func assertPolicyAvailable() async throws {
    let profiles = MobileActionProfile.allCases
    guard !profiles.isEmpty else { throw Failure.profileTableEmpty }
    let floor = MobileActionProfile.mostRestrictive(profiles)
    guard floor == .observe else { throw Failure.latticeFloorMoved(floor) }
  }
}

/// Refuses the bind when the installed Codex is not a supported build.
///
/// Unsupported Codex disables LAN outright; it is not a degraded mode (plan
/// §2 invariant 2). The probe runs `codex --version` and a schema digest,
/// both read-only, and consumes no allowance.
public struct BridgeCodexSupportProbe: ListenerCodexSupportProbing {
  /// Raised when the installed Codex is not supported.
  public enum Failure: Error, Equatable, Sendable {
    case unsupported(CodexCompatibilityDecision)
  }

  private let probe: any CodexCompatibilityProbing
  private let policy: CodexCompatibilityPolicy

  public init(probe: any CodexCompatibilityProbing, policy: CodexCompatibilityPolicy) {
    self.probe = probe
    self.policy = policy
  }

  public func assertCodexSupported() async throws {
    let report = try await probe.probe()
    let decision = policy.evaluate(report)
    guard decision == .supported else { throw Failure.unsupported(decision) }
  }
}

// MARK: - The assembly

/// Everything the bridge needs to serve one LAN session, wired together.
///
/// Construction is deliberately explicit rather than defaulted: each
/// collaborator is built by the caller and handed in, so there is no hidden
/// singleton and a test can substitute any one of them.
public struct BridgeNetworkAssembly: Sendable {
  /// Mac-authoritative device grants.
  public let authority: DeviceGrantAuthority
  /// Authenticated-session state machine.
  public let sessions: SessionCoordinator
  /// Pairing state machine, or `nil` when pairing is closed.
  public let pairing: PairingCoordinator?
  /// Scoped observation.
  public let broker: DeviceObservationBroker
  /// The single path from a network message to a semantic mutation.
  public let gateway: NetworkCommandGateway
  /// TLS identity source.
  public let tls: BridgeSecureEnclaveTLSProvider
  /// Startup prerequisite probes other than TLS.
  public let grantProbe: BridgeGrantAuthorityProbe
  public let policyProbe: BridgeCapabilityPolicyProbe
  public let codexProbe: BridgeCodexSupportProbe
  /// Ceilings the listener enforces.
  public let ceilings: ListenerCeilings
  /// Closed-code logger.
  public let logger: any ListenerLogging
  /// Where the verification phrase and the completed proposal go.
  ///
  /// Defaults to discarding both, which is correct only for a listener with
  /// no pairing UI. A production assembly supplies
  /// ``BridgePairingObserver``; without it a completed pairing produces no
  /// grant and the phrase is never shown.
  public let pairingObserver: any ListenerPairingObserving

  public init(
    authority: DeviceGrantAuthority,
    sessions: SessionCoordinator,
    pairing: PairingCoordinator?,
    broker: DeviceObservationBroker,
    gateway: NetworkCommandGateway,
    tls: BridgeSecureEnclaveTLSProvider,
    codexProbe: BridgeCodexSupportProbe,
    ceilings: ListenerCeilings = ListenerCeilings(),
    logger: any ListenerLogging = DiscardingListenerLogger(),
    pairingObserver: any ListenerPairingObserving = DiscardingListenerPairingObserver()
  ) {
    self.authority = authority
    self.sessions = sessions
    self.pairing = pairing
    self.broker = broker
    self.gateway = gateway
    self.tls = tls
    self.grantProbe = BridgeGrantAuthorityProbe(authority: authority)
    self.policyProbe = BridgeCapabilityPolicyProbe()
    self.codexProbe = codexProbe
    self.ceilings = ceilings
    self.logger = logger
    self.pairingObserver = pairingObserver
  }

  /// Builds one complete, enabled listener over a validated LAN binding.
  ///
  /// **A fresh handshake handler and frame registry per listener.** The
  /// hardened listener's lifecycle is one-shot, so enabling again builds
  /// another; giving the new one a new registry means directional codecs
  /// minted under a previous LAN session can never be claimed by a
  /// connection on this one. Their counters are the whole point, and a
  /// counter resumed from a stale registry is a replay window.
  ///
  /// The registry handed to `frameProvider` is the *same object* the
  /// handshake handler writes into. Wiring two different registries would
  /// authenticate connections that could then open nothing, which is the
  /// kind of failure that only appears against a real device.
  public func makeConfiguration(
    enablement: ListenerEnablement,
    binding: ListenerInterfaceBinding,
    interfacePolicy: ListenerInterfacePolicy = ListenerInterfacePolicy()
  ) -> ListenerConfiguration {
    let handshake = CoordinatorListenerHandshakeHandler(
      pairing: pairing,
      session: sessions,
      frames: ListenerSessionFrameRegistry(),
      observer: pairingObserver
    )
    return ListenerConfiguration.enabled(
      by: enablement,
      binding: binding,
      interfacePolicy: interfacePolicy,
      ceilings: ceilings,
      handshake: handshake,
      observation: BrokerObservationHandler(broker: broker),
      commands: GatewayCommandHandler(gateway: gateway),
      frameProvider: handshake.frameRegistry,
      logger: logger
    )
  }

  /// The startup prerequisites this assembly's listeners are gated on.
  public func makePrerequisites() -> ListenerPrerequisites {
    ListenerPrerequisites(
      identity: tls,
      grantAuthority: grantProbe,
      policy: policyProbe,
      codex: codexProbe
    )
  }

  /// Builds the listener. Splitting the configuration out above is what lets
  /// a test assert *what was wired* without binding a socket — the defect
  /// this file exists to close was invisible precisely because the wiring
  /// was unreachable from outside the actor.
  public func makeListener(
    enablement: ListenerEnablement,
    binding: ListenerInterfaceBinding,
    interfacePolicy: ListenerInterfacePolicy = ListenerInterfacePolicy()
  ) -> HardenedWSSListener {
    HardenedWSSListener(
      configuration: makeConfiguration(
        enablement: enablement,
        binding: binding,
        interfacePolicy: interfacePolicy
      ),
      prerequisites: makePrerequisites()
    )
  }

  /// The LAN control the Mac menu drives.
  ///
  /// `makeListener` is a closure rather than a stored listener because the
  /// controller must be able to build a *new* one on every enable; the
  /// binding is resolved at that moment too, so an interface that changed
  /// while LAN was off is picked up rather than remembered.
  ///
  /// Resolving no eligible interface throws, and the controller reports it as
  /// `startupDenied` — off, with a reason, never a partial bind.
  public func makeLANController(
    interfacePolicy: ListenerInterfacePolicy = ListenerInterfacePolicy(),
    bonjour: ListenerBonjourCoordinator = ListenerBonjourCoordinator()
  ) -> BridgeLANController {
    BridgeLANController(
      makeListener: {
        // The enablement is minted here, at the point the user's toggle
        // reached the controller, and is never stored.
        guard
          let binding = try? ListenerInterfaceDiscovery.firstEligibleBinding(
            policy: interfacePolicy)
        else {
          return UnavailableBridgeListener()
        }
        return makeListener(
          enablement: .userRequested(),
          binding: binding,
          interfacePolicy: interfacePolicy
        )
      },
      bonjour: bonjour
    )
  }
}

/// Stands in when no eligible LAN interface could be resolved.
///
/// The controller's contract is that `makeListener` returns something; a
/// listener that refuses to start turns "no Wi-Fi or Ethernet is eligible"
/// into the same closed `startupDenied` the menu already shows for every
/// other refused prerequisite, rather than a distinct crash path.
struct UnavailableBridgeListener: BridgeListenerControlling {
  func start() async throws -> ListenerEndpoint {
    throw ListenerStartupFailure.networkConfigurationIneligible
  }

  func stop() async throws {}
}
